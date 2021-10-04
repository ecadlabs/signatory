package awskms

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"os"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/request"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/ecadlabs/signatory/pkg/config"
	"github.com/ecadlabs/signatory/pkg/cryptoutils"
	"github.com/ecadlabs/signatory/pkg/vault"

	"gopkg.in/yaml.v3"
)

type Kmsapi interface {
	ListKeys(input *kms.ListKeysInput) (*kms.ListKeysOutput, error)
	Sign(input *kms.SignInput) (*kms.SignOutput, error)
	GetPublicKeyWithContext(aws.Context, *kms.GetPublicKeyInput, ...request.Option) (*kms.GetPublicKeyOutput, error)
}

// Config contains AWS KMS backend configuration
type Config struct {
	UserName    string `yaml:"user_name" validate:"required"`
	AccessKeyID string `yaml:"access_key_id" validate:"required"`
	AccessKey   string `yaml:"secret_access_key" validate:"required"`
	Region      string `yaml:"region" validate:"required"`
}

type Vault struct {
	Kmsapi Kmsapi
	// Kmsapi kmsiface.KMSAPI
	Config Config
}

// awsKMSKey represents a key stored in AWS KMS
type awsKMSKey struct {
	key *kms.GetPublicKeyOutput
	pub *ecdsa.PublicKey
}

type awsKMSIterator struct {
	ctx  context.Context
	v    *Vault
	indx int
	lko  *kms.ListKeysOutput
}

// PublicKey returns encoded public key
func (c *awsKMSKey) PublicKey() crypto.PublicKey {
	return c.pub
}

// ID returnd a unique key ID
func (c *awsKMSKey) ID() string {
	return *c.key.KeyId
}

func (kv *Vault) GetPublicKey(ctx context.Context, keyID string) (vault.StoredKey, error) {

	pkresp, err := kv.Kmsapi.GetPublicKeyWithContext(ctx, &kms.GetPublicKeyInput{
		KeyId: &keyID,
	})
	if err != nil {
		return nil, err
	}

	if *pkresp.KeyUsage != kms.KeyUsageTypeSignVerify {
		return nil, errors.New("key usage must be SIGN_VERIFY")
	}

	pkixKey, err := x509.ParsePKIXPublicKey(pkresp.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	ecKey, ok := pkixKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("key is not EC: %T", ecKey)
	}

	return &awsKMSKey{
		key: pkresp,
		pub: ecKey,
	}, nil
}

func (c *awsKMSIterator) Next() (key vault.StoredKey, err error) {
	if c.lko.Keys == nil {
		return nil, fmt.Errorf("key list empty")
	}

	if c.indx >= len(c.lko.Keys) {
		return nil, vault.ErrDone
	}

	c.indx += 1
	return c.v.GetPublicKey(c.ctx, *c.lko.Keys[c.indx-1].KeyId)

}

// ListPublicKeys returns a list of keys stored under the backend
func (c *Vault) ListPublicKeys(ctx context.Context) vault.StoredKeysIterator {

	var lkout *kms.ListKeysOutput
	var err error
	var lkin *kms.ListKeysInput

	for {
		lkout, err = c.Kmsapi.ListKeys(lkin)
		if err != nil {
			return nil
		}
		if !*lkout.Truncated {
			break
		}
		lkin.Marker = lkout.NextMarker
	}

	return &awsKMSIterator{
		ctx:  ctx,
		v:    c,
		lko:  lkout,
		indx: 0,
	}
}

// Name returns backend name
func (c *Vault) Name() string {
	return "AWSKMS"
}

func (c *Vault) Sign(ctx context.Context, digest []byte, key vault.StoredKey) (cryptoutils.Signature, error) {
	kid := key.ID()
	sout, err := c.Kmsapi.Sign(&kms.SignInput{
		KeyId:            &kid,
		Message:          digest,
		MessageType:      aws.String(kms.MessageTypeDigest),
		SigningAlgorithm: aws.String(kms.SigningAlgorithmSpecEcdsaSha256),
	})
	if err != nil {
		return nil, err
	}

	var sig struct {
		R *big.Int
		S *big.Int
	}

	if _, err = asn1.Unmarshal(sout.Signature, &sig); err != nil {
		return nil, fmt.Errorf("(AWSKMS/%s): %v", kid, err)
	}

	pubkey := key.(*awsKMSKey)
	return &cryptoutils.ECDSASignature{
		R:     sig.R,
		S:     sig.S,
		Curve: pubkey.pub.Curve,
	}, nil
}

// New creates new AWS KMS backend
func New(ctx context.Context, config *Config) (*Vault, error) {
	os.Setenv("AWS_ACCESS_KEY_ID", config.AccessKeyID)
	os.Setenv("AWS_SECRET_ACCESS_KEY", config.AccessKey)
	os.Setenv("AWS_REGION", config.Region)
	sess := session.Must(session.NewSession())

	api := kms.New(sess)
	return &Vault{
		Kmsapi: api,
		Config: *config,
	}, nil
}

func init() {
	vault.RegisterVault("awskms", func(ctx context.Context, node *yaml.Node) (vault.Vault, error) {
		var conf Config
		if node == nil || node.Kind == 0 {
			return nil, errors.New("(AWSKMS): config is missing")
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
