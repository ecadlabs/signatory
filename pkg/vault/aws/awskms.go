package awskms

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"os"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/ecadlabs/gotez/signature"
	"github.com/ecadlabs/signatory/pkg/config"
	"github.com/ecadlabs/signatory/pkg/cryptoutils"
	"github.com/ecadlabs/signatory/pkg/vault"

	"gopkg.in/yaml.v3"
)

// Config contains AWS KMS backend configuration
type Config struct {
	UserName    string `yaml:"user_name" validate:"required"`
	AccessKeyID string `yaml:"access_key_id"`
	AccessKey   string `yaml:"secret_access_key"`
	Region      string `yaml:"region" validate:"required"`
}

type Vault struct {
	kmsapi *kms.KMS
	config Config
}

// awsKMSKey represents a key stored in AWS KMS
type awsKMSKey struct {
	key *kms.GetPublicKeyOutput
	pub *ecdsa.PublicKey
}

type awsKMSIterator struct {
	ctx    context.Context
	v      *Vault
	kmsapi *kms.KMS
	lko    *kms.ListKeysOutput
	index  int
}

// PublicKey returns encoded public key
func (c *awsKMSKey) PublicKey() crypto.PublicKey {
	return c.pub
}

// ID returnd a unique key ID
func (c *awsKMSKey) ID() string {
	return *c.key.KeyId
}

func (v *Vault) GetPublicKey(ctx context.Context, keyID string) (vault.StoredKey, error) {
	pkresp, err := v.kmsapi.GetPublicKeyWithContext(ctx, &kms.GetPublicKeyInput{
		KeyId: &keyID,
	})
	if err != nil {
		return nil, err
	}

	if *pkresp.KeyUsage != kms.KeyUsageTypeSignVerify {
		return nil, errors.New("key usage must be SIGN_VERIFY")
	}

	pkixKey, err := cryptoutils.ParsePKIXPublicKey(pkresp.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	ecKey, ok := pkixKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("%w: %T", vault.ErrKey, ecKey)
	}

	return &awsKMSKey{
		key: pkresp,
		pub: ecKey,
	}, nil
}

func (i *awsKMSIterator) Next() (key vault.StoredKey, err error) {
	if i.lko == nil || i.index == len(i.lko.Keys) {
		// get next page
		if i.lko != nil && i.lko.NextMarker == nil {
			// end of the list
			return nil, vault.ErrDone
		}
		var lkin *kms.ListKeysInput
		if i.lko != nil {
			lkin = &kms.ListKeysInput{
				Marker: i.lko.NextMarker,
			}
		} // otherwise leave it nil
		i.lko, err = i.kmsapi.ListKeys(lkin)
		if err != nil {
			return nil, err
		}
	}

	key, err = i.v.GetPublicKey(i.ctx, *i.lko.Keys[i.index].KeyId)
	i.index += 1
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			case "AccessDeniedException":
				return i.Next() // If access denied, return Next
			}
		}
	}
	return key, err
}

// ListPublicKeys returns a list of keys stored under the backend
func (v *Vault) ListPublicKeys(ctx context.Context) vault.StoredKeysIterator {
	return &awsKMSIterator{
		ctx:    ctx,
		v:      v,
		kmsapi: v.kmsapi,
	}
}

// Name returns backend name
func (v *Vault) Name() string {
	return "AWSKMS"
}

func (v *Vault) SignMessage(ctx context.Context, message []byte, key vault.StoredKey) (cryptoutils.Signature, error) {
	digest := cryptoutils.Digest(message)
	kid := key.ID()
	sout, err := v.kmsapi.Sign(&kms.SignInput{
		KeyId:            &kid,
		Message:          digest[:],
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
		return nil, fmt.Errorf("(AWSKMS/%s): %w", kid, err)
	}

	pubkey := key.(*awsKMSKey)
	return &signature.ECDSA{
		R:     sig.R,
		S:     sig.S,
		Curve: pubkey.pub.Curve,
	}, nil
}

// New creates new AWS KMS backend
func New(ctx context.Context, config *Config) (*Vault, error) {
	if config.AccessKeyID != "" {
		os.Setenv("AWS_ACCESS_KEY_ID", config.AccessKeyID)
		os.Setenv("AWS_SECRET_ACCESS_KEY", config.AccessKey)
	}
	os.Setenv("AWS_REGION", config.Region)
	sess := session.Must(session.NewSession())

	api := kms.New(sess)
	return &Vault{
		kmsapi: api,
		config: *config,
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
