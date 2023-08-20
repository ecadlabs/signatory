package hashicorp

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"

	"github.com/ecadlabs/signatory/pkg/config"
	"github.com/ecadlabs/signatory/pkg/crypt"
	"github.com/ecadlabs/signatory/pkg/vault"
	"github.com/hashicorp/vault/api"
	auth "github.com/hashicorp/vault/api/auth/approle"
	"gopkg.in/yaml.v3"
)

// Config contains Hashcorp Vault backend configuration
type Config struct {
	Address        string `yaml:"address"`
	RoleID         string `yaml:"roleID"`
	SecretID       string `yaml:"secretID"`
	TLSCaCert      string `yaml:"tlsCaCert"`
	TLSClientCert  string `yaml:"tlsClientCert"`
	TLSClientKey   string `yaml:"tlsClientKey"`
	*TransitConfig `yaml:"transitConfig"`
}

type Vault struct {
	client     *api.Client
	RoleID     string
	SecretID   string
	transitCfg *TransitConfig
}

// vaultKey represents a key stored in Hashcorp Vault
type vaultKey struct {
	id  string
	pub crypt.PublicKey
}

// PublicKey returns encoded public key
func (k *vaultKey) PublicKey() crypt.PublicKey {
	return k.pub
}

// ID returnd a unique key ID
func (k *vaultKey) ID() string {
	return k.id
}

type iterator struct {
	ctx     context.Context
	v       *Vault
	keyList []string
	index   int
}

func init() {
	vault.RegisterVault("hashicorpvault", func(ctx context.Context, node *yaml.Node) (vault.Vault, error) {
		var conf Config
		if node == nil || node.Kind == 0 {
			return nil, errors.New("(HashicorpVault): config is missing")
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

// New creates new Hashicorp Vault backend
func New(ctx context.Context, cfg *Config) (*Vault, error) {
	vaultConfig := &api.Config{
		Address: cfg.Address,
	}

	// verify if address is https
	parsedurl, err := url.Parse(cfg.Address)
	if err != nil {
		return nil, fmt.Errorf("unable to parse vault address: %w", err)
	}
	if parsedurl.Scheme == "https" {
		tlsCfg := api.TLSConfig{
			CACert:     cfg.TLSCaCert,
			ClientCert: cfg.TLSClientCert,
			ClientKey:  cfg.TLSClientKey,
		}
		if err := vaultConfig.ConfigureTLS(&tlsCfg); err != nil {
			return nil, fmt.Errorf("unable to configure TLS: %w", err)
		}
	}

	client, err := api.NewClient(vaultConfig)
	if err != nil {
		return nil, err
	}

	vault := &Vault{
		client:     client,
		transitCfg: cfg.TransitConfig,
		RoleID:     cfg.RoleID,
		SecretID:   cfg.SecretID,
	}

	if err = vault.login(); err != nil {
		return nil, err
	}

	return vault, nil
}

// Name returns backend name
func (v *Vault) Name() string {
	return "HASHICORP_VAULT"
}

func (v *Vault) login() error {
	appRoleAuth, err := auth.NewAppRoleAuth(v.RoleID, &auth.SecretID{FromString: v.SecretID})
	if err != nil {
		return fmt.Errorf("unable to initialize AppRole auth method: %w", err)
	}

	authInfo, err := v.client.Auth().Login(context.Background(), appRoleAuth)
	if err != nil {
		return fmt.Errorf("unable to login to AppRole auth method: %w", err)
	}
	if authInfo == nil {
		return fmt.Errorf("no auth info was returned after login")
	}

	return nil
}

// ListPublicKeys returns a list of keys stored under the backend
func (v *Vault) ListPublicKeys(ctx context.Context) vault.StoredKeysIterator {
	return &iterator{
		ctx: ctx,
		v:   v,
	}
}

func (i *iterator) Next() (key vault.StoredKey, err error) {
	if i.keyList == nil {
		i.keyList, err = i.v.Transit().ListKeys()
		if err != nil {
			return nil, err
		}
	}
	if i.index == len(i.keyList) {
		// end of the list
		return nil, vault.ErrDone
	}

	key, err = i.v.GetPublicKey(i.ctx, i.keyList[i.index])
	i.index += 1

	if err != nil {
		return nil, err
	}

	return key, nil
}

func (v *Vault) GetPublicKey(ctx context.Context, keyID string) (vault.StoredKey, error) {
	wrappingPubKeyString, err := v.Transit().GetKeyWithContext(ctx, keyID)
	if err != nil {
		return nil, err
	}

	pubKeyBytes, err := base64.StdEncoding.DecodeString(wrappingPubKeyString)
	if err != nil {
		return nil, err
	}

	// Ensure the public key length is correct for EdDSA (32 bytes)
	if len(pubKeyBytes) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid public key length")
	}

	// Convert the bytes to an Ed25519 public key
	eddsaPublicKey := ed25519.PublicKey(pubKeyBytes)

	cryptPubKey, err := crypt.NewPublicKeyFrom(eddsaPublicKey)
	if err != nil {
		return nil, err
	}

	return &vaultKey{
		id:  keyID,
		pub: cryptPubKey,
	}, nil
}

func (v *Vault) SignMessage(ctx context.Context, message []byte, key vault.StoredKey) (crypt.Signature, error) {
	digest := crypt.DigestFunc(message)

	sout, err := v.Transit().Sign(key.ID(), digest[:], &SignOpts{Hash: "sha2-256", Preshashed: false})
	if err != nil {
		return nil, err
	}

	sig, err := crypt.NewSignatureFromBytes(sout, key.PublicKey())
	if err != nil {
		return nil, err
	}
	return sig, nil
}
