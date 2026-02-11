package vault

import (
	"context"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"encoding/pem"
	stderr "errors"
	"fmt"
	"time"

	kms "cloud.google.com/go/kms/apiv1"
	kmspb "cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/ecadlabs/gotez/v2/crypt"
	"github.com/ecadlabs/signatory/pkg/config"
	"github.com/ecadlabs/signatory/pkg/cryptoutils"
	"github.com/ecadlabs/signatory/pkg/cryptoutils/x509"
	"github.com/ecadlabs/signatory/pkg/errors"
	"github.com/ecadlabs/signatory/pkg/utils"
	"github.com/ecadlabs/signatory/pkg/utils/gcp"
	"github.com/ecadlabs/signatory/pkg/vault"
	kwp "github.com/google/tink/go/kwp/subtle"
	"github.com/googleapis/gax-go/v2/apierror"
	"github.com/segmentio/ksuid"
	log "github.com/sirupsen/logrus"
	"google.golang.org/api/iterator"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"gopkg.in/yaml.v3"
)

// Default values for timeout and retry configuration
const (
	defaultTimeout    = 10 * time.Second
	defaultMaxRetries = 3
	maxAllowedRetries = 100 // Cap to prevent integer overflow in 1 + maxRetries
	baseBackoff       = 100 * time.Millisecond
	maxBackoff        = 10 * time.Second
)

// Config contains Google Cloud KMS backend configuration
type Config struct {
	gcp.Config `yaml:",inline"`
	Project    string `yaml:"project" validate:"required"`
	Location   string `yaml:"location" validate:"required"`
	KeyRing    string `yaml:"key_ring" validate:"required"`
	Timeout    int    `yaml:"timeout"`     // Per-request timeout in seconds (default: 10s)
	MaxRetries *int   `yaml:"max_retries"` // Max retry attempts after initial try (default: 3, set to 0 to disable retries)
}

func (c *Config) getTimeout() time.Duration {
	if c.Timeout > 0 {
		return time.Duration(c.Timeout) * time.Second
	}
	return defaultTimeout
}

func (c *Config) getMaxRetries() int {
	if c.MaxRetries != nil && *c.MaxRetries >= 0 {
		return min(*c.MaxRetries, maxAllowedRetries)
	}
	return defaultMaxRetries
}

// keyRingName returns full Google Cloud KMS key ring path
func (c *Config) keyRingName() string {
	return fmt.Sprintf("projects/%s/locations/%s/keyRings/%s", c.Project, c.Location, c.KeyRing)
}

// Vault is a Google Cloud KMS backend
type Vault struct {
	client *kms.KeyManagementClient
	config Config
}

// cloudKMSKey represents a key stored in Google Cloud KMS
type cloudKMSKey struct {
	key *kmspb.CryptoKeyVersion
	pub crypt.PublicKey
	v   *Vault
}

func (k *cloudKMSKey) PublicKey() crypt.PublicKey { return k.pub }      // PublicKey returns encoded public key
func (k *cloudKMSKey) ID() string                 { return k.key.Name } // ID returnd a unique key ID
func (k *cloudKMSKey) Vault() vault.Vault         { return k.v }

func isRetryableError(err error) bool {
	if err == nil {
		return false
	}
	st, ok := status.FromError(err)
	if !ok {
		return false
	}
	switch st.Code() {
	case codes.DeadlineExceeded, codes.Unavailable, codes.ResourceExhausted:
		return true
	default:
		return false
	}
}

func isErrorSkippable(code codes.Code) bool {
	switch code {
	case codes.PermissionDenied, // No permission to access key
		codes.NotFound,           // Key/version was destroyed
		codes.FailedPrecondition: // Key version disabled or in invalid state
		return true
	default:
		return false
	}
}

func (kmsKey *cloudKMSKey) Sign(ctx context.Context, message []byte, opt *vault.SignOptions) (crypt.Signature, error) {
	digest := crypt.DigestFunc(message)
	req := kmspb.AsymmetricSignRequest{
		Name: kmsKey.key.Name,
		Digest: &kmspb.Digest{
			Digest: &kmspb.Digest_Sha256{
				Sha256: digest[:],
			},
		},
	}

	timeout := kmsKey.v.config.getTimeout()
	maxRetries := kmsKey.v.config.getMaxRetries()
	maxAttempts := 1 + maxRetries

	var lastErr error
	for attempt := 0; attempt < maxAttempts; attempt++ {
		// Apply per-attempt timeout
		attemptCtx, cancel := context.WithTimeout(ctx, timeout)

		resp, err := kmsKey.v.client.AsymmetricSign(attemptCtx, &req)
		cancel()

		if err == nil {
			sig, err := crypt.NewSignatureFromBytes(resp.Signature, kmsKey.pub)
			if err != nil {
				return nil, fmt.Errorf("(CloudKMS/%s): %w", kmsKey.v.config.keyRingName(), err)
			}
			return sig, nil
		}

		lastErr = err

		// Check if we should retry
		if !isRetryableError(err) {
			break
		}

		// Check if parent context is cancelled
		if ctx.Err() != nil {
			break
		}

		// Log and wait before retry (not on last attempt)
		if attempt < maxAttempts-1 {
			// Exponential backoff: 100ms, 200ms, 400ms... capped at maxBackoff
			// Guard against overflow: 1<<30 is safe, larger may overflow on 64-bit
			backoff := maxBackoff
			if attempt < 30 {
				backoff = min(baseBackoff*time.Duration(1<<attempt), maxBackoff)
			}

			log.WithFields(log.Fields{
				"key_ring": kmsKey.v.config.keyRingName(),
				"attempt":  attempt + 1,
				"backoff":  backoff,
				"error":    err.Error(),
			}).Warn("CloudKMS AsymmetricSign failed, retrying")

			select {
			case <-time.After(backoff):
			case <-ctx.Done():
				return nil, fmt.Errorf("(CloudKMS/%s) AsymmetricSign: %w", kmsKey.v.config.keyRingName(), ctx.Err())
			}
		}
	}

	return nil, fmt.Errorf("(CloudKMS/%s) AsymmetricSign: %w", kmsKey.v.config.keyRingName(), lastErr)
}

func getAlgorithm(curve elliptic.Curve) kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm {
	if curve == elliptic.P256() {
		return kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256
	}
	return 0
}

func (c *Vault) getPublicKey(ctx context.Context, name string) (crypt.PublicKey, error) {
	pk, err := c.client.GetPublicKey(ctx, &kmspb.GetPublicKeyRequest{Name: name})
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode([]byte(pk.Pem))
	return cryptoutils.ParsePKIXPublicKey(block.Bytes)
}

type cloudKMSIterator struct {
	ctx     context.Context
	vault   *Vault
	keyIter *kms.CryptoKeyIterator
	verIter *kms.CryptoKeyVersionIterator
}

// Next implements vault.StoredKeysIterator
func (c *cloudKMSIterator) Next() (vault.KeyReference, error) {
	if c.keyIter == nil {
		return nil, vault.ErrDone
	}

	for {
		// get next version
		var (
			ver *kmspb.CryptoKeyVersion
			err error
		)
		if c.verIter != nil {
			ver, err = c.verIter.Next()
			if err != nil && err != iterator.Done {
				var apiErr *apierror.APIError
				if stderr.As(err, &apiErr) && isErrorSkippable(apiErr.GRPCStatus().Code()) {
					c.verIter = nil
					continue
				}
				return nil, fmt.Errorf("(CloudKMS/%s) ListCryptoKeys: %w", c.vault.config.keyRingName(), err)
			}
		}
		if c.verIter == nil || err == iterator.Done {
			// get next key
			var (
				key *kmspb.CryptoKey
				err error
			)
			for {
				key, err = c.keyIter.Next()
				if err != nil {
					if err == iterator.Done {
						c.keyIter = nil
						return nil, vault.ErrDone
					} else {
						var apiErr *apierror.APIError
						if stderr.As(err, &apiErr) && isErrorSkippable(apiErr.GRPCStatus().Code()) {
							c.keyIter = nil
							return nil, vault.ErrDone
						}
						return nil, fmt.Errorf("(CloudKMS/%s) ListCryptoKeys: %w", c.vault.config.keyRingName(), err)
					}
				}
				// List signing EC keys only
				if key.Purpose == kmspb.CryptoKey_ASYMMETRIC_SIGN {
					break
				}
			}
			// get key versions
			c.verIter = c.vault.client.ListCryptoKeyVersions(c.ctx, &kmspb.ListCryptoKeyVersionsRequest{Parent: key.Name})
		} else {
			if ver.State == kmspb.CryptoKeyVersion_ENABLED {
				pub, err := c.vault.getPublicKey(c.ctx, ver.Name)
				if err != nil {
					var apiErr *apierror.APIError
					if stderr.As(err, &apiErr) && isErrorSkippable(apiErr.GRPCStatus().Code()) {
						continue
					}
					return nil, fmt.Errorf("(CloudKMS/%s) getPublicKey: %w", c.vault.config.keyRingName(), err)
				} else {
					return &cloudKMSKey{
						key: ver,
						pub: pub,
						v:   c.vault,
					}, nil
				}
			}
		}
	}
}

// List returns a list of keys stored under the backend
func (c *Vault) List(ctx context.Context) vault.KeyIterator {
	return &cloudKMSIterator{
		ctx:     ctx,
		vault:   c,
		keyIter: c.client.ListCryptoKeys(ctx, &kmspb.ListCryptoKeysRequest{Parent: c.config.keyRingName()}),
	}
}

// PKCS#11 CKM_RSA_AES_KEY_WRAP
func wrapPrivateKey(pubKey *rsa.PublicKey, priv crypt.PrivateKey) ([]byte, error) {
	pkcs8Key, err := cryptoutils.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, err
	}

	// Generate an ephemeral 256-bit AES wrapping key
	aesKey := make([]byte, 32)
	if _, err = rand.Read(aesKey); err != nil {
		return nil, err
	}

	// Encrypt the wrapping key with job's private key
	// SHA-1 is required
	encAesKey, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, pubKey, aesKey, []byte{})
	if err != nil {
		return nil, err
	}

	// Wrap the key
	wrapper, err := kwp.NewKWP(aesKey)
	if err != nil {
		return nil, err
	}

	wrappedKey, err := wrapper.Wrap(pkcs8Key)
	if err != nil {
		return nil, err
	}

	// Concatenate
	res := make([]byte, len(encAesKey)+len(wrappedKey))
	copy(res, encAesKey)
	copy(res[len(encAesKey):], wrappedKey)

	return res, nil
}

// Import imports a private key
func (c *Vault) Import(ctx context.Context, pk crypt.PrivateKey, opt utils.Options) (vault.KeyReference, error) {
	keyName, ok, err := opt.GetString("name")
	if err != nil {
		return nil, fmt.Errorf("(CloudKMS/%s): %w", c.config.keyRingName(), err)
	}
	if !ok {
		keyName = "signatory-imported-" + ksuid.New().String()
	}

	ecdsaKey, ok := pk.(*crypt.ECDSAPrivateKey)
	if !ok {
		return nil, fmt.Errorf("(CloudKMS/%s) unsupported key type: %T", c.config.keyRingName(), pk)
	}

	algo := getAlgorithm(ecdsaKey.Curve)
	if algo == 0 {
		return nil, fmt.Errorf("(CloudKMS/%s) unsupported curve: %s", c.config.keyRingName(), ecdsaKey.Params().Name)
	}

	// Create a key
	newKeyReq := kmspb.CreateCryptoKeyRequest{
		Parent:      c.config.keyRingName(),
		CryptoKeyId: keyName,
		CryptoKey: &kmspb.CryptoKey{
			Purpose: kmspb.CryptoKey_ASYMMETRIC_SIGN,
			VersionTemplate: &kmspb.CryptoKeyVersionTemplate{
				ProtectionLevel: kmspb.ProtectionLevel_HSM,
				Algorithm:       algo,
			},
		},
		SkipInitialVersionCreation: true,
	}

	newKey, err := c.client.CreateCryptoKey(ctx, &newKeyReq)
	if err != nil {
		return nil, fmt.Errorf("(CloudKMS/%s) CreateCryptoKey: %w", c.config.keyRingName(), err)
	}

	// Create an import job
	jobReq := kmspb.CreateImportJobRequest{
		Parent:      c.config.keyRingName(),
		ImportJobId: "signatory-import-job-" + ksuid.New().String(),
		ImportJob: &kmspb.ImportJob{
			ImportMethod:    kmspb.ImportJob_RSA_OAEP_4096_SHA1_AES_256,
			ProtectionLevel: kmspb.ProtectionLevel_HSM,
		},
	}

	job, err := c.client.CreateImportJob(ctx, &jobReq)
	if err != nil {
		return nil, fmt.Errorf("(CloudKMS/%s) CreateImportJob: %w", c.config.keyRingName(), err)
	}

	// Rely on context for cancellation
	for job.State == kmspb.ImportJob_PENDING_GENERATION {
		job, err = c.client.GetImportJob(ctx, &kmspb.GetImportJobRequest{Name: job.Name})
		if err != nil {
			return nil, fmt.Errorf("(CloudKMS/%s) GetImportJob: %w", c.config.keyRingName(), err)
		}
	}

	if job.State != kmspb.ImportJob_ACTIVE {
		return nil, fmt.Errorf("(CloudKMS/%s): unexpected import job state (%v)", c.config.keyRingName(), job)
	}

	// Decode job's public key
	pemBlock, _ := pem.Decode([]byte(job.PublicKey.Pem))
	opaqueJobKey, err := x509.ParsePKIXPublicKey(pemBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("(CloudKMS/%s): %w", c.config.keyRingName(), err)
	}

	jobPubKey, ok := opaqueJobKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("(CloudKMS/%s): not a RSA public key: %T", c.config.keyRingName(), opaqueJobKey)
	}

	// Wrap the key
	wrappedKey, err := wrapPrivateKey(jobPubKey, pk)
	if err != nil {
		return nil, fmt.Errorf("(CloudKMS/%s): %w", c.config.keyRingName(), err)
	}

	// Do import
	importReq := kmspb.ImportCryptoKeyVersionRequest{
		Parent:    newKey.Name,
		Algorithm: algo,
		ImportJob: job.Name,
		WrappedKeyMaterial: &kmspb.ImportCryptoKeyVersionRequest_RsaAesWrappedKey{
			RsaAesWrappedKey: wrappedKey,
		},
	}

	ver, err := c.client.ImportCryptoKeyVersion(ctx, &importReq)
	if err != nil {
		return nil, fmt.Errorf("(CloudKMS/%s) ImportCryptoKeyVersion: %w", c.config.keyRingName(), err)
	}

	for ver.State == kmspb.CryptoKeyVersion_PENDING_IMPORT {
		ver, err = c.client.GetCryptoKeyVersion(ctx, &kmspb.GetCryptoKeyVersionRequest{Name: ver.Name})
		if err != nil {
			return nil, fmt.Errorf("(CloudKMS/%s) ImportCryptoKeyVersion: %w", c.config.keyRingName(), err)
		}
	}

	if ver.State != kmspb.CryptoKeyVersion_ENABLED {
		return nil, fmt.Errorf("(CloudKMS/%s): unexpected key version state (%v)", c.config.keyRingName(), ver)
	}

	return &cloudKMSKey{
		key: ver,
		pub: (*crypt.ECDSAPublicKey)(&ecdsaKey.PublicKey),
		v:   c,
	}, nil
}

// Name returns backend name
func (c *Vault) Name() string {
	return fmt.Sprintf("CloudKMS/%s", c.config.keyRingName())
}

func (c *Vault) Close(context.Context) error { return nil }

// New creates new Google Cloud KMS backend
func New(ctx context.Context, config *Config) (*Vault, error) {
	opts, err := gcp.NewGCPOption(ctx, &config.Config)
	if err != nil {
		return nil, fmt.Errorf("(CloudKMS/%s): %w", config.keyRingName(), err)
	}

	client, err := kms.NewKeyManagementClient(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("(CloudKMS/%s): %w", config.keyRingName(), err)
	}

	return &Vault{
		client: client,
		config: *config,
	}, nil
}

func init() {
	vault.RegisterVault("cloudkms", func(ctx context.Context, node *yaml.Node, global config.GlobalContext) (vault.Vault, error) {
		var conf Config
		if node == nil || node.Kind == 0 {
			return nil, errors.New("(CloudKMS): config is missing")
		}
		if err := node.Decode(&conf); err != nil {
			return nil, err
		}

		if err := config.Validator().Struct(&conf); err != nil {
			return nil, err
		}

		return New(ctx, &conf)
	})
}

var _ vault.Importer = &Vault{}
