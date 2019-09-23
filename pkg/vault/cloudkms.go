package vault

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"

	"github.com/davecgh/go-spew/spew"

	kms "cloud.google.com/go/kms/apiv1"
	"github.com/ecadlabs/signatory/pkg/crypto"
	"github.com/ecadlabs/signatory/pkg/signatory"
	"github.com/google/tink/go/subtle/kwp"
	"github.com/segmentio/ksuid"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
	kmspb "google.golang.org/genproto/googleapis/cloud/kms/v1"
)

type CloudKMSVaultConfig struct {
	ServiceAccountKey string
	Project           string
	Location          string
	KeyRing           string
	HSM               bool
}

func (c *CloudKMSVaultConfig) keyRing() string {
	return fmt.Sprintf("projects/%s/locations/%s/keyRings/%s", c.Project, c.Location, c.KeyRing)
}

type CloudKMSVault struct {
	client *kms.KeyManagementClient
	config CloudKMSVaultConfig
}

type CloudKMSKey struct {
	key *kmspb.CryptoKeyVersion
	pub *ecdsa.PublicKey
}

func (c *CloudKMSKey) Curve() string {
	return crypto.CurveP256
}

// TODO make it accept a context and return an error?
func (c *CloudKMSKey) PublicKey() []byte {
	return toCompressedFormat(c.pub.X.Bytes(), c.pub.Y.Bytes())
}

func (c *CloudKMSKey) ID() string {
	return c.key.Name
}

func (c *CloudKMSVault) getPublicKey(ctx context.Context, name string) (*ecdsa.PublicKey, error) {
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

func (c *CloudKMSVault) ListPublicKeys(ctx context.Context) (keys []signatory.StoredKey, err error) {
	it := c.client.ListCryptoKeys(ctx, &kmspb.ListCryptoKeysRequest{Parent: c.config.keyRing()})
	for {
		resp, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("(CloudKMS/%s) ListCryptoKeys: %v", c.config.keyRing(), err)
		}

		// List signing EC keys only
		if resp.Purpose != kmspb.CryptoKey_ASYMMETRIC_SIGN {
			continue
		}

		// Get key versions
		vit := c.client.ListCryptoKeyVersions(ctx, &kmspb.ListCryptoKeyVersionsRequest{Parent: resp.Name})
		for {
			ver, err := vit.Next()
			if err == iterator.Done {
				break
			}
			if err != nil {
				return nil, fmt.Errorf("(CloudKMS/%s) ListCryptoKeyVersions: %v", c.config.keyRing(), err)
			}

			// List signing EC keys only
			if ver.Algorithm != kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256 {
				continue
			}

			ecKey, err := c.getPublicKey(ctx, ver.Name)
			if err != nil {
				return nil, fmt.Errorf("(CloudKMS/%s) getPublicKey: %v", c.config.keyRing(), err)
			}

			keys = append(keys, &CloudKMSKey{
				key: ver,
				pub: ecKey,
			})

		}
	}
	return
}

func (c *CloudKMSVault) GetPublicKey(ctx context.Context, keyID string) (signatory.StoredKey, error) {
	req := kmspb.GetCryptoKeyVersionRequest{
		Name: keyID,
	}

	resp, err := c.client.GetCryptoKeyVersion(ctx, &req)
	if err != nil {
		return nil, fmt.Errorf("(CloudKMS/%s) GetCryptoKeyVersion: %v", c.config.keyRing(), err)
	}

	if resp.Algorithm != kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256 {
		return nil, fmt.Errorf("(CloudKMS/%s): unsupported key type (%v)", c.config.keyRing(), resp)
	}

	ecKey, err := c.getPublicKey(ctx, resp.Name)
	if err != nil {
		return nil, fmt.Errorf("(CloudKMS/%s) getPublicKey: %v", c.config.keyRing(), err)
	}

	return &CloudKMSKey{
		key: resp,
		pub: ecKey,
	}, nil
}

func (c *CloudKMSVault) Sign(ctx context.Context, digest []byte, key signatory.StoredKey) ([]byte, error) {
	kmsKey, ok := key.(*CloudKMSKey)
	if !ok {
		return nil, fmt.Errorf("(CloudKMS/%s): not a CloudKMS key: %T ", c.config.keyRing(), key)
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
		return nil, fmt.Errorf("(CloudKMS/%s) AsymmetricSign: %v", c.config.keyRing(), err)
	}

	return resp.Signature, nil
}

// TODO move to crypto
func jwkToECPK(jwk *signatory.JWK) (*ecdsa.PrivateKey, error) {
	curve := crypto.GetCurve(jwk.Curve)
	if curve == nil {
		return nil, fmt.Errorf("Unknown curve: %s", jwk.Curve)
	}

	x, err := base64.RawURLEncoding.DecodeString(jwk.X)
	if err != nil {
		return nil, err
	}

	y, err := base64.RawURLEncoding.DecodeString(jwk.Y)
	if err != nil {
		return nil, err
	}

	d, err := base64.RawURLEncoding.DecodeString(jwk.D)
	if err != nil {
		return nil, err
	}

	return &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: curve,
			X:     big.NewInt(0).SetBytes(x),
			Y:     big.NewInt(0).SetBytes(y),
		},
		D: big.NewInt(0).SetBytes(d),
	}, nil
}

func (c *CloudKMSVault) Import(ctx context.Context, jwk *signatory.JWK) (string, error) {
	// Encode the key to be imported
	pk, err := jwkToECPK(jwk)
	if err != nil {
		return "", fmt.Errorf("(CloudKMS/%s): %v", c.config.keyRing(), err)
	}
	spew.Dump(pk)

	encPK, err := x509.MarshalPKCS8PrivateKey(pk)
	if err != nil {
		return "", fmt.Errorf("(CloudKMS/%s): %v", c.config.keyRing(), err)
	}
	spew.Dump(encPK)

	// Create a key
	newKeyReq := kmspb.CreateCryptoKeyRequest{
		Parent:      c.config.keyRing(),
		CryptoKeyId: "signatory-imported-" + ksuid.New().String(),
		CryptoKey: &kmspb.CryptoKey{
			Purpose: kmspb.CryptoKey_ASYMMETRIC_SIGN,
			VersionTemplate: &kmspb.CryptoKeyVersionTemplate{
				ProtectionLevel: kmspb.ProtectionLevel_HSM,
				Algorithm:       kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256,
			},
		},
		SkipInitialVersionCreation: true,
	}

	newKey, err := c.client.CreateCryptoKey(ctx, &newKeyReq)
	if err != nil {
		return "", fmt.Errorf("(CloudKMS/%s) CreateCryptoKey: %v", c.config.keyRing(), err)
	}

	// Create an import job
	importProtectionLevel := kmspb.ProtectionLevel_SOFTWARE
	if c.config.HSM {
		importProtectionLevel = kmspb.ProtectionLevel_HSM
	}

	jobReq := kmspb.CreateImportJobRequest{
		Parent:      c.config.keyRing(),
		ImportJobId: "signatory-import-job-" + ksuid.New().String(),
		ImportJob: &kmspb.ImportJob{
			ImportMethod:    kmspb.ImportJob_RSA_OAEP_4096_SHA1_AES_256,
			ProtectionLevel: importProtectionLevel,
		},
	}

	job, err := c.client.CreateImportJob(ctx, &jobReq)
	if err != nil {
		return "", fmt.Errorf("(CloudKMS/%s) CreateImportJob: %v", c.config.keyRing(), err)
	}

	// Rely on context for cancellation
	for job.State == kmspb.ImportJob_PENDING_GENERATION {
		job, err = c.client.GetImportJob(ctx, &kmspb.GetImportJobRequest{Name: job.Name})
		if err != nil {
			return "", fmt.Errorf("(CloudKMS/%s) GetImportJob: %v", c.config.keyRing(), err)
		}
	}

	if job.State != kmspb.ImportJob_ACTIVE {
		return "", fmt.Errorf("(CloudKMS/%s): unexpected import job state (%v)", c.config.keyRing(), job)
	}

	// Decode job's public key
	pemBlock, _ := pem.Decode([]byte(job.PublicKey.Pem))
	opaqueJobKey, err := x509.ParsePKIXPublicKey(pemBlock.Bytes)
	if err != nil {
		return "", fmt.Errorf("(CloudKMS/%s): %v", c.config.keyRing(), err)
	}

	jobPubKey, ok := opaqueJobKey.(*rsa.PublicKey)
	if !ok {
		return "", fmt.Errorf("(CloudKMS/%s): not a RSA public key: %T", c.config.keyRing(), opaqueJobKey)
	}

	// Generate an ephemeral 256-bit AES wrapping key
	aesKey := make([]byte, 32)
	if _, err = rand.Read(aesKey); err != nil {
		return "", fmt.Errorf("(CloudKMS/%s): %v", c.config.keyRing(), err)
	}

	// Encrypt the wrapping key with job's private key
	encAesKey, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, jobPubKey, aesKey, []byte{})

	// Wrap the key
	wrapper, err := kwp.NewKWP(aesKey)
	if err != nil {
		return "", fmt.Errorf("(CloudKMS/%s): %v", c.config.keyRing(), err)
	}

	aesWrappedKey, err := wrapper.Wrap(encPK)
	if err != nil {
		return "", fmt.Errorf("(CloudKMS/%s): %v", c.config.keyRing(), err)
	}

	// Concatenate
	wrappedKey := make([]byte, len(encAesKey)+len(aesWrappedKey))
	copy(wrappedKey, encAesKey)
	copy(wrappedKey[len(encAesKey):], aesWrappedKey)

	// Do import
	importReq := kmspb.ImportCryptoKeyVersionRequest{
		Parent:    newKey.Name,
		Algorithm: kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256,
		ImportJob: job.Name,
		WrappedKeyMaterial: &kmspb.ImportCryptoKeyVersionRequest_RsaAesWrappedKey{
			RsaAesWrappedKey: wrappedKey,
		},
	}

	ver, err := c.client.ImportCryptoKeyVersion(ctx, &importReq)
	if err != nil {
		return "", fmt.Errorf("(CloudKMS/%s) ImportCryptoKeyVersion: %v", c.config.keyRing(), err)
	}

	for ver.State == kmspb.CryptoKeyVersion_PENDING_IMPORT {
		ver, err = c.client.GetCryptoKeyVersion(ctx, &kmspb.GetCryptoKeyVersionRequest{Name: ver.Name})
		if err != nil {
			return "", fmt.Errorf("(CloudKMS/%s) ImportCryptoKeyVersion: %v", c.config.keyRing(), err)
		}
	}

	if ver.State != kmspb.CryptoKeyVersion_ENABLED {
		return "", fmt.Errorf("(CloudKMS/%s): key version job state (%v)", c.config.keyRing(), ver)
	}

	return ver.Name, nil
}

func (c *CloudKMSVault) Name() string {
	return "CloudKMS"
}

func NewCloudKMSVault(ctx context.Context, config *CloudKMSVaultConfig) (*CloudKMSVault, error) {
	var opts []option.ClientOption
	if config.ServiceAccountKey != "" {
		opts = []option.ClientOption{option.WithCredentialsJSON([]byte(config.ServiceAccountKey))}
	}

	client, err := kms.NewKeyManagementClient(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("(CloudKMS/%s): %v", config.keyRing(), err)
	}

	return &CloudKMSVault{
		client: client,
		config: *config,
	}, nil
}
