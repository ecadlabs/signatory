package awskms

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/aws/smithy-go"
	"github.com/ecadlabs/gotez/v2/crypt"
	"github.com/ecadlabs/signatory/pkg/cryptoutils"
	"github.com/ecadlabs/signatory/pkg/vault"

	"gopkg.in/yaml.v3"
)

// Config contains AWS KMS backend configuration
type Config struct {
	AccessKeyID string `yaml:"access_key_id"`
	AccessKey   string `yaml:"secret_access_key"`
	Region      string `yaml:"region"`
}

type Vault struct {
	client *kms.Client
	config Config
}

// awsKMSKey represents a key stored in AWS KMS
type awsKMSKey struct {
	key *kms.GetPublicKeyOutput
	pub crypt.PublicKey
	v   *Vault
}

type awsKMSIterator struct {
	ctx    context.Context
	v      *Vault
	client *kms.Client
	lko    *kms.ListKeysOutput
	index  int
}

// PublicKey returns encoded public key
func (k *awsKMSKey) PublicKey() crypt.PublicKey { return k.pub }
func (k *awsKMSKey) String() string             { return *k.key.KeyId }
func (k *awsKMSKey) Vault() vault.Vault         { return k.v }

func (k *awsKMSKey) Sign(ctx context.Context, message []byte) (crypt.Signature, error) {
	digest := crypt.DigestFunc(message)
	sout, err := k.v.client.Sign(ctx, &kms.SignInput{
		KeyId:            k.key.KeyId,
		Message:          digest[:],
		MessageType:      types.MessageTypeDigest,
		SigningAlgorithm: types.SigningAlgorithmSpecEcdsaSha256,
	})
	if err != nil {
		return nil, err
	}

	sig, err := crypt.NewSignatureFromBytes(sout.Signature, k.pub)
	if err != nil {
		return nil, fmt.Errorf("(AWSKMS/%s): %w", *k.key.KeyId, err)
	}
	return sig, nil
}

func (i *awsKMSIterator) Next() (key vault.KeyReference, err error) {
	for {
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

			i.lko, err = i.client.ListKeys(i.ctx, lkin)
			if err != nil {
				return nil, err
			}
		}

		key, err = i.v.getPublicKey(i.ctx, i.lko.Keys[i.index].KeyId)
		i.index += 1

		var kmserr smithy.APIError
		if err == nil {
			return key, nil
		} else if errors.As(err, &kmserr) {
			if kmserr.ErrorCode() != "AccessDeniedException" {
				return nil, err
			}
		} else if err != crypt.ErrUnsupportedKeyType {
			return nil, err
		}
	}
}

func (v *Vault) getPublicKey(ctx context.Context, keyID *string) (*awsKMSKey, error) {
	pkresp, err := v.client.GetPublicKey(ctx, &kms.GetPublicKeyInput{
		KeyId: keyID,
	})
	if err != nil {
		return nil, err
	}

	if pkresp.KeyUsage != types.KeyUsageTypeSignVerify {
		return nil, errors.New("key usage must be SIGN_VERIFY")
	}

	pkixKey, err := cryptoutils.ParsePKIXPublicKey(pkresp.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	pub, err := crypt.NewPublicKeyFrom(pkixKey)
	if err != nil {
		return nil, err
	}

	return &awsKMSKey{
		key: pkresp,
		pub: pub,
		v:   v,
	}, nil
}

// List returns a list of keys stored under the backend
func (v *Vault) List(ctx context.Context) vault.KeyIterator {
	return &awsKMSIterator{
		ctx:    ctx,
		v:      v,
		client: v.client,
	}
}

// Name returns backend name
func (v *Vault) Name() string {
	return "AWSKMS"
}

func (v *Vault) Close(context.Context) error {
	return nil
}

func NewConfig(ctx context.Context, config *Config) (aws.Config, error) {
	if config.AccessKeyID != "" {
		os.Setenv("AWS_ACCESS_KEY_ID", config.AccessKeyID)
		os.Setenv("AWS_SECRET_ACCESS_KEY", config.AccessKey)
	}
	if config.Region != "" {
		os.Setenv("AWS_REGION", config.Region)
	}
	return awsconfig.LoadDefaultConfig(ctx)
}

// New creates new AWS KMS backend
func New(ctx context.Context, config *Config) (*Vault, error) {
	cfg, err := NewConfig(ctx, config)
	if err != nil {
		return nil, err
	}

	client := kms.NewFromConfig(cfg)
	return &Vault{
		client: client,
		config: *config,
	}, nil
}

func init() {
	vault.RegisterVault("awskms", func(ctx context.Context, node *yaml.Node) (vault.Vault, error) {
		var conf Config
		if node != nil {
			if err := node.Decode(&conf); err != nil {
				return nil, err
			}
		}
		return New(ctx, &conf)
	})
}
