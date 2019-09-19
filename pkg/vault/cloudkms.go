package vault

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"

	kms "cloud.google.com/go/kms/apiv1"
	"github.com/ecadlabs/signatory/pkg/crypto"
	"github.com/ecadlabs/signatory/pkg/signatory"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
	kmspb "google.golang.org/genproto/googleapis/cloud/kms/v1"
)

type CloudKMSVaultConfig struct {
	ServiceAccountKey string
	Project           string
	Location          string
	KeyRing           string
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
	req := kmspb.GetPublicKeyRequest{
		Name: name,
	}

	pk, err := c.client.GetPublicKey(ctx, &req)
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
	req := kmspb.ListCryptoKeysRequest{
		Parent: c.config.keyRing(),
	}

	it := c.client.ListCryptoKeys(ctx, &req)
	for {
		resp, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("(CloudKMS/%s): %v", c.config.keyRing(), err)
		}

		// List signing EC keys only
		if resp.Purpose != kmspb.CryptoKey_ASYMMETRIC_SIGN {
			continue
		}

		// Get key versions
		vreq := kmspb.ListCryptoKeyVersionsRequest{
			Parent: resp.Name,
		}

		vit := c.client.ListCryptoKeyVersions(ctx, &vreq)
		for {
			ver, err := vit.Next()
			if err == iterator.Done {
				break
			}
			if err != nil {
				return nil, fmt.Errorf("(CloudKMS/%s): %v", c.config.keyRing(), err)
			}

			// List signing EC keys only
			if ver.Algorithm != kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256 {
				continue
			}

			ecKey, err := c.getPublicKey(ctx, ver.Name)
			if err != nil {
				return nil, fmt.Errorf("(CloudKMS/%s): %v", c.config.keyRing(), err)
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
		return nil, fmt.Errorf("(CloudKMS/%s): %v", c.config.keyRing(), err)
	}

	if resp.Algorithm != kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256 {
		return nil, fmt.Errorf("(CloudKMS/%s): unsupported key type: %v", c.config.keyRing(), resp)
	}

	ecKey, err := c.getPublicKey(ctx, resp.Name)
	if err != nil {
		return nil, fmt.Errorf("(CloudKMS/%s): %v", c.config.keyRing(), err)
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
		return nil, fmt.Errorf("(CloudKMS/%s): %v", c.config.keyRing(), err)
	}

	val, err := base64.RawURLEncoding.DecodeString(string(resp.Signature))
	if err != nil {
		return nil, fmt.Errorf("(CloudKMS/%s): %v", c.config.keyRing(), err)
	}

	return val, nil
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
