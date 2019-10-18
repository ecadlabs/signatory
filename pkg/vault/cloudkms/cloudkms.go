package vault

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"net/http"

	kms "cloud.google.com/go/kms/apiv1"
	"github.com/ecadlabs/signatory/pkg/config"
	"github.com/ecadlabs/signatory/pkg/cryptoutils"
	"github.com/ecadlabs/signatory/pkg/errors"
	"github.com/ecadlabs/signatory/pkg/vault"
	"github.com/google/tink/go/subtle/kwp"
	"github.com/segmentio/ksuid"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
	kmspb "google.golang.org/genproto/googleapis/cloud/kms/v1"
	"gopkg.in/yaml.v3"
)

// Config contains Google Cloud KMS backend configuration
type Config struct {
	ApplicationCredentialsData string `yaml:"application_credentials_data"`
	ApplicationCredentials     string `yaml:"application_credentials"`
	Project                    string `yaml:"project" validate:"required"`
	Location                   string `yaml:"location" validate:"required"`
	KeyRing                    string `yaml:"key_ring" validate:"required"`
}

// KeyRingName returns full Google Cloud KMS key ring path
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
	pub *ecdsa.PublicKey
}

// PublicKey returns encoded public key
func (c *cloudKMSKey) PublicKey() crypto.PublicKey {
	return c.pub
}

// ID returnd a unique key ID
func (c *cloudKMSKey) ID() string {
	return c.key.Name
}

func getAlgorithm(curve elliptic.Curve) kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm {
	if curve == elliptic.P256() {
		return kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256
	}
	return 0
}

func (c *Vault) getPublicKey(ctx context.Context, name string) (*ecdsa.PublicKey, error) {
	pk, err := c.client.GetPublicKey(ctx, &kmspb.GetPublicKeyRequest{Name: name})
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode([]byte(pk.Pem))
	pkixKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	ecKey, ok := pkixKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("key is not EC: %T", ecKey)
	}

	return ecKey, nil
}

type cloudKMSIterator struct {
	ctx context.Context
	v   *Vault
	ki  *kms.CryptoKeyIterator
	vi  *kms.CryptoKeyVersionIterator
}

// Next implements vault.StoredKeysIterator
func (c *cloudKMSIterator) Next() (key vault.StoredKey, err error) {
	if c.ki == nil {
		return nil, vault.ErrDone
	}

	var ver *kmspb.CryptoKeyVersion
	for {
		if c.vi != nil {
			ver, err = c.vi.Next()
		}
		if c.vi == nil || err == iterator.Done {
			for {
				var resp *kmspb.CryptoKey
				for {
					resp, err = c.ki.Next()
					if err == iterator.Done {
						c.ki = nil
						return nil, vault.ErrDone
					}
					if err != nil {
						return nil, fmt.Errorf("(CloudKMS/%s) ListCryptoKeys: %v", c.v.config.keyRingName(), err)
					}
					// List signing EC keys only
					if resp.Purpose == kmspb.CryptoKey_ASYMMETRIC_SIGN {
						break
					}
				}

				// Get key versions
				c.vi = c.v.client.ListCryptoKeyVersions(c.ctx, &kmspb.ListCryptoKeyVersionsRequest{Parent: resp.Name})
				ver, err = c.vi.Next()
				if err == nil {
					break
				} else if err != iterator.Done {
					return nil, fmt.Errorf("(CloudKMS/%s) ListCryptoKeyVersions: %v", c.v.config.keyRingName(), err)
				}
			}
		} else if err != nil {
			return nil, fmt.Errorf("(CloudKMS/%s) ListCryptoKeyVersions: %v", c.v.config.keyRingName(), err)
		}

		if ver.State == kmspb.CryptoKeyVersion_ENABLED {
			break
		}
	}

	ecKey, err := c.v.getPublicKey(c.ctx, ver.Name)
	if err != nil {
		return nil, fmt.Errorf("(CloudKMS/%s) getPublicKey: %v", c.v.config.keyRingName(), err)
	}

	return &cloudKMSKey{
		key: ver,
		pub: ecKey,
	}, nil
}

// ListPublicKeys returns a list of keys stored under the backend
func (c *Vault) ListPublicKeys(ctx context.Context) vault.StoredKeysIterator {
	return &cloudKMSIterator{
		ctx: ctx,
		v:   c,
		ki:  c.client.ListCryptoKeys(ctx, &kmspb.ListCryptoKeysRequest{Parent: c.config.keyRingName()}),
	}
}

// GetPublicKey returns a public key by given ID
func (c *Vault) GetPublicKey(ctx context.Context, keyID string) (vault.StoredKey, error) {
	req := kmspb.GetCryptoKeyVersionRequest{
		Name: keyID,
	}

	resp, err := c.client.GetCryptoKeyVersion(ctx, &req)
	if err != nil {
		return nil, fmt.Errorf("(CloudKMS/%s) GetCryptoKeyVersion: %v", c.config.keyRingName(), err)
	}

	if resp.State != kmspb.CryptoKeyVersion_ENABLED {
		return nil, fmt.Errorf("(CloudKMS/%s) Key version is not enabled: %s", c.config.keyRingName(), keyID)
	}

	ecKey, err := c.getPublicKey(ctx, resp.Name)
	if err != nil {
		return nil, fmt.Errorf("(CloudKMS/%s) getPublicKey: %v", c.config.keyRingName(), err)
	}

	return &cloudKMSKey{
		key: resp,
		pub: ecKey,
	}, nil
}

// Sign performs signing operation
func (c *Vault) Sign(ctx context.Context, digest []byte, key vault.StoredKey) (cryptoutils.Signature, error) {
	kmsKey, ok := key.(*cloudKMSKey)
	if !ok {
		return nil, errors.Wrap(fmt.Errorf("(CloudKMS/%s): not a CloudKMS key: %T ", c.config.keyRingName(), key), http.StatusBadRequest)
	}

	req := kmspb.AsymmetricSignRequest{
		Name: kmsKey.key.Name,
		Digest: &kmspb.Digest{
			Digest: &kmspb.Digest_Sha256{
				Sha256: digest,
			},
		},
	}

	resp, err := c.client.AsymmetricSign(ctx, &req)
	if err != nil {
		return nil, fmt.Errorf("(CloudKMS/%s) AsymmetricSign: %v", c.config.keyRingName(), err)
	}

	var sig cryptoutils.ECDSASignature
	if _, err = asn1.Unmarshal(resp.Signature, &sig); err != nil {
		return nil, fmt.Errorf("(CloudKMS/%s) AsymmetricSign: %v", c.config.keyRingName(), err)
	}

	return &sig, nil
}

// PKCS#11 CKM_RSA_AES_KEY_WRAP
func wrapPrivateKey(pubKey *rsa.PublicKey, pk crypto.PrivateKey) ([]byte, error) {
	pkcs8Key, err := cryptoutils.MarshalPKCS8PrivateKey(pk)
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
func (c *Vault) Import(ctx context.Context, pk cryptoutils.PrivateKey) (vault.StoredKey, error) {
	ecdsaKey, ok := pk.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("(CloudKMS/%s) Unsupported key type: %T", c.config.keyRingName(), pk)
	}

	algo := getAlgorithm(ecdsaKey.Curve)
	if algo == 0 {
		return nil, fmt.Errorf("(CloudKMS/%s) Unsupported curve: %s", c.config.keyRingName(), ecdsaKey.Params().Name)
	}

	// Create a key
	newKeyReq := kmspb.CreateCryptoKeyRequest{
		Parent:      c.config.keyRingName(),
		CryptoKeyId: "signatory-imported-" + ksuid.New().String(),
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
		return nil, fmt.Errorf("(CloudKMS/%s) CreateCryptoKey: %v", c.config.keyRingName(), err)
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
		return nil, fmt.Errorf("(CloudKMS/%s) CreateImportJob: %v", c.config.keyRingName(), err)
	}

	// Rely on context for cancellation
	for job.State == kmspb.ImportJob_PENDING_GENERATION {
		job, err = c.client.GetImportJob(ctx, &kmspb.GetImportJobRequest{Name: job.Name})
		if err != nil {
			return nil, fmt.Errorf("(CloudKMS/%s) GetImportJob: %v", c.config.keyRingName(), err)
		}
	}

	if job.State != kmspb.ImportJob_ACTIVE {
		return nil, fmt.Errorf("(CloudKMS/%s): unexpected import job state (%v)", c.config.keyRingName(), job)
	}

	// Decode job's public key
	pemBlock, _ := pem.Decode([]byte(job.PublicKey.Pem))
	opaqueJobKey, err := x509.ParsePKIXPublicKey(pemBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("(CloudKMS/%s): %v", c.config.keyRingName(), err)
	}

	jobPubKey, ok := opaqueJobKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("(CloudKMS/%s): not a RSA public key: %T", c.config.keyRingName(), opaqueJobKey)
	}

	// Wrap the key
	wrappedKey, err := wrapPrivateKey(jobPubKey, pk)
	if err != nil {
		return nil, fmt.Errorf("(CloudKMS/%s): %v", c.config.keyRingName(), err)
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
		return nil, fmt.Errorf("(CloudKMS/%s) ImportCryptoKeyVersion: %v", c.config.keyRingName(), err)
	}

	for ver.State == kmspb.CryptoKeyVersion_PENDING_IMPORT {
		ver, err = c.client.GetCryptoKeyVersion(ctx, &kmspb.GetCryptoKeyVersionRequest{Name: ver.Name})
		if err != nil {
			return nil, fmt.Errorf("(CloudKMS/%s) ImportCryptoKeyVersion: %v", c.config.keyRingName(), err)
		}
	}

	if ver.State != kmspb.CryptoKeyVersion_ENABLED {
		return nil, fmt.Errorf("(CloudKMS/%s): unexpected key version state (%v)", c.config.keyRingName(), ver)
	}

	return &cloudKMSKey{
		key: ver,
		pub: &ecdsaKey.PublicKey,
	}, nil
}

// Name returns backend name
func (c *Vault) Name() string {
	return "CloudKMS"
}

// VaultName returns vault name
func (c *Vault) VaultName() string {
	return c.config.keyRingName()
}

// NewVault creates new Google Cloud KMS backend
func NewVault(ctx context.Context, config *Config) (*Vault, error) {
	var opts []option.ClientOption

	if config.ApplicationCredentialsData != "" {
		opts = []option.ClientOption{option.WithCredentialsJSON([]byte(config.ApplicationCredentialsData))}
	} else if config.ApplicationCredentials != "" {
		opts = []option.ClientOption{option.WithCredentialsFile(config.ApplicationCredentials)}
	}

	client, err := kms.NewKeyManagementClient(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("(CloudKMS/%s): %v", config.keyRingName(), err)
	}

	return &Vault{
		client: client,
		config: *config,
	}, nil
}

func init() {
	vault.RegisterVault("cloudkms", func(ctx context.Context, node *yaml.Node) (vault.Vault, error) {
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

		return NewVault(ctx, &conf)
	})
}

var _ vault.Importer = &Vault{}
