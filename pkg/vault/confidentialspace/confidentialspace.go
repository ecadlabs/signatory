package confidentialspace

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"iter"
	"net"
	"os"
	"path/filepath"
	"sync"

	tz "github.com/ecadlabs/gotez/v2"
	"github.com/ecadlabs/gotez/v2/b58"
	"github.com/ecadlabs/gotez/v2/crypt"
	"github.com/ecadlabs/signatory/pkg/config"
	"github.com/ecadlabs/signatory/pkg/cryptoutils"
	"github.com/ecadlabs/signatory/pkg/utils"
	"github.com/ecadlabs/signatory/pkg/vault"
	"github.com/ecadlabs/signatory/pkg/vault/confidentialspace/rpc"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
)

const (
	DefaultPort = 2000
)

const defaultFile = "confidential_space_keys.json"

///////////////////////////////////////////////////////////////////////////////////////////

type StorageConfig struct {
	Driver string    `yaml:"driver"`
	Config yaml.Node `yaml:"config"`
}

type result[T any] interface {
	Result() iter.Seq[T]
	Err() error
}

type keyBlobStorage interface {
	GetKeys(ctx context.Context) (result[*encryptedKey], error)
	ImportKey(ctx context.Context, encryptedKey *encryptedKey) error
}

///////////////////////////////////////////////////////////////////////////////////////////

type encryptedKey struct {
	PublicKeyHash       tz.PublicKeyHash `json:"public_key_hash"`
	EncryptedPrivateKey []byte           `json:"encrypted_private_key"`
}

func (e *encryptedKey) UnmarshalJSON(data []byte) error {
	type Alias encryptedKey
	aux := &struct {
		PublicKeyHash string `json:"public_key_hash"`
		*Alias
	}{
		Alias: (*Alias)(e),
	}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	pkh, err := b58.ParsePublicKeyHash([]byte(aux.PublicKeyHash))
	if err != nil {
		return err
	}
	e.PublicKeyHash = pkh
	return nil
}

///////////////////////////////////////////////////////////////////////////////////////////

type Config struct {
	ConfidentialSpaceHost string         `yaml:"host"`
	ConfidentialSpacePort string         `yaml:"port"`
	WipProviderPath       string         `yaml:"wip_provider_path"`
	EncryptionKeyPath     string         `yaml:"encryption_key_path"`
	Storage               *StorageConfig `yaml:"storage"`
}

func resolve[T comparable](value T, ev string) T {
	var zero T
	if value == zero {
		if env := os.Getenv(ev); env != "" {
			var tmp T
			if _, err := fmt.Sscanf(env, "%v", &tmp); err == nil {
				return tmp
			}
		}
	}
	return value
}

func populateConfig(c *Config) *Config {
	if c == nil {
		var zero Config
		c = &zero
	}
	return &Config{
		ConfidentialSpaceHost: resolve(c.ConfidentialSpaceHost, "CONFIDENTIAL_SPACE_HOST"),
		ConfidentialSpacePort: resolve(c.ConfidentialSpacePort, "CONFIDENTIAL_SPACE_PORT"),
		WipProviderPath:       resolve(c.WipProviderPath, "GCP_WIP_PROVIDER_PATH"),
		EncryptionKeyPath:     resolve(c.EncryptionKeyPath, "GCP_KMS_ENCRYPTION_KEY_PATH"),
		Storage:               c.Storage,
	}
}

///////////////////////////////////////////////////////////////////////////////////////////

type ConfidentialSpaceVault[C any] struct {
	client  *rpc.Client[C]
	storage keyBlobStorage
	keys    []*confidentialKey
	mtx     sync.Mutex
}

func (v *ConfidentialSpaceVault[C]) List(ctx context.Context) vault.KeyIterator {
	v.mtx.Lock()
	defer v.mtx.Unlock()

	snap := v.keys
	i := 0
	return vault.IteratorFunc(func() (key vault.KeyReference, err error) {
		if i >= len(snap) {
			return nil, vault.ErrDone
		}
		k := &confidentialKeyRef[C]{
			confidentialKey: snap[i],
			v:               v,
		}
		i++
		return k, nil
	})
}

func (v *ConfidentialSpaceVault[C]) Close(ctx context.Context) (err error) {
	err = v.client.Close()
	return err
}

func (v *ConfidentialSpaceVault[C]) Name() string { return "ConfidentialSpace" }

func (v *ConfidentialSpaceVault[C]) Import(ctx context.Context, pk crypt.PrivateKey, opt utils.Options) (vault.KeyReference, error) {
	rpcPk, err := rpc.NewPrivateKey(pk)
	if err != nil {
		return nil, fmt.Errorf("(ConfidentialSpace): %w", err)
	}

	v.mtx.Lock()
	defer v.mtx.Unlock()

	res, err := v.client.ImportUnencrypted(ctx, rpcPk)
	if err != nil {
		return nil, fmt.Errorf("(ConfidentialSpace): %w", err)
	}
	p, err := res.PublicKey.PublicKey()
	if err != nil {
		return nil, fmt.Errorf("(ConfidentialSpace): %w", err)
	}
	key := &confidentialKey{
		pub:    p,
		handle: res.Handle,
	}
	v.keys = append(v.keys, key)

	if err := v.storage.ImportKey(ctx, &encryptedKey{
		PublicKeyHash:       p.Hash(),
		EncryptedPrivateKey: res.EncryptedPrivateKey,
	}); err != nil {
		return nil, fmt.Errorf("(ConfidentialSpace): %w", err)
	}

	return &confidentialKeyRef[C]{
		confidentialKey: key,
		v:               v,
	}, nil
}

func (v *ConfidentialSpaceVault[C]) Generate(ctx context.Context, keyType *cryptoutils.KeyType, n int) (vault.KeyIterator, error) {
	var kt rpc.KeyType
	switch keyType {
	case cryptoutils.KeyEd25519:
		kt = rpc.KeyEd25519
	case cryptoutils.KeySecp256k1:
		kt = rpc.KeySecp256k1
	case cryptoutils.KeyP256:
		kt = rpc.KeyNISTP256
	case cryptoutils.KeyBLS12_381:
		kt = rpc.KeyBLS
	default:
		return nil, fmt.Errorf("(ConfidentialSpace): unsupported key type %v", keyType)
	}

	v.mtx.Lock()
	defer v.mtx.Unlock()

	var imported []*confidentialKey
	for i := 0; i < n; i++ {
		res, err := v.client.GenerateAndImport(ctx, kt)
		if err != nil {
			return nil, fmt.Errorf("(ConfidentialSpace): %w", err)
		}
		p, err := res.PublicKey.PublicKey()
		if err != nil {
			return nil, fmt.Errorf("(ConfidentialSpace): %w", err)
		}
		key := &confidentialKey{
			pub:    p,
			handle: res.Handle,
		}
		v.keys = append(v.keys, key)
		if err := v.storage.ImportKey(ctx, &encryptedKey{
			PublicKeyHash:       p.Hash(),
			EncryptedPrivateKey: res.EncryptedPrivateKey,
		}); err != nil {
			return nil, fmt.Errorf("(ConfidentialSpace): %w", err)
		}
		imported = append(imported, key)
	}

	i := 0
	return vault.IteratorFunc(func() (key vault.KeyReference, err error) {
		if i >= len(imported) {
			return nil, vault.ErrDone
		}
		k := &confidentialKeyRef[C]{
			confidentialKey: imported[i],
			v:               v,
		}
		i++
		return k, nil
	}), nil
}

///////////////////////////////////////////////////////////////////////////////////////////

type confidentialKey struct {
	pub    crypt.PublicKey
	handle uint64
}

type confidentialKeyRef[C any] struct {
	*confidentialKey
	v *ConfidentialSpaceVault[C]
}

func (r *confidentialKeyRef[C]) PublicKey() crypt.PublicKey { return r.pub }
func (r *confidentialKeyRef[C]) Vault() vault.Vault         { return r.v }

func (r *confidentialKeyRef[C]) Sign(ctx context.Context, message []byte) (crypt.Signature, error) {
	r.v.mtx.Lock()
	defer r.v.mtx.Unlock()

	sig, err := r.v.client.Sign(ctx, r.handle, message)
	if err != nil {
		return nil, fmt.Errorf("(ConfidentialSpace): %w", err)
	}

	res, err := sig.Signature()
	if err != nil {
		return nil, fmt.Errorf("(ConfidentialSpace): %w", err)
	}
	return res, nil
}

func (r *confidentialKeyRef[C]) ProvePossession(ctx context.Context) (crypt.Signature, error) {
	r.v.mtx.Lock()
	defer r.v.mtx.Unlock()

	sig, err := r.v.client.ProvePossession(ctx, r.handle)
	if err != nil {
		return nil, fmt.Errorf("(Nitro): %w", err)
	}

	res, err := sig.Signature()
	if err != nil {
		return nil, fmt.Errorf("(Nitro): %w", err)
	}
	return res, nil
}

///////////////////////////////////////////////////////////////////////////////////////////

func New(ctx context.Context, config *Config, global config.GlobalContext) (*ConfidentialSpaceVault[rpc.ConfidentialSpaceCredentials], error) {
	var sc *StorageConfig
	if config != nil {
		sc = config.Storage
	}
	storage, err := newStorage(ctx, sc, global)
	if err != nil {
		return nil, fmt.Errorf("(ConfidentialSpace): %w", err)
	}
	return newWithStorage(ctx, config, storage)
}

func newStorage(ctx context.Context, conf *StorageConfig, global config.GlobalContext) (keyBlobStorage, error) {
	if conf != nil {
		switch conf.Driver {
		case "file":
			var path string
			if conf.Config.IsZero() {
				path = filepath.Join(global.GetBaseDir(), defaultFile)
			} else if err := conf.Config.Decode(&path); err == nil {
				path = os.ExpandEnv(path)
			} else {
				return nil, err
			}
			return newFileStorage(path)
		default:
			return nil, fmt.Errorf("(ConfidentialSpace): unknown key storage %s", conf.Driver)
		}
	} else {
		path := filepath.Join(global.GetBaseDir(), defaultFile)
		return newFileStorage(path)
	}
}

func newWithStorage(ctx context.Context, config *Config, storage keyBlobStorage) (*ConfidentialSpaceVault[rpc.ConfidentialSpaceCredentials], error) {
	conf := populateConfig(config)

	if conf.ConfidentialSpaceHost == "" {
		return nil, errors.New("(ConfidentialSpace): missing confidential space host")
	}
	if conf.EncryptionKeyPath == "" {
		return nil, errors.New("(ConfidentialSpace): missing encryption key path")
	}

	rpcCred := rpc.ConfidentialSpaceCredentials{
		WipProviderPath:   conf.WipProviderPath,
		EncryptionKeyPath: conf.EncryptionKeyPath,
	}
	if !rpcCred.IsValid() {
		return nil, errors.New("(ConfidentialSpace): invalid credentials")
	}

	addr := net.JoinHostPort(conf.ConfidentialSpaceHost, conf.ConfidentialSpacePort)
	log.Infof("(ConfidentialSpace): connecting to the enclave signer on %v...", addr)
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("(ConfidentialSpace): %w", err)
	}

	v, err := newWithConn(ctx, conn, &rpcCred, storage)
	if err != nil {
		return nil, err
	}
	return v, nil
}

func newWithConn[C any](ctx context.Context, conn net.Conn, credentials *C, storage keyBlobStorage) (*ConfidentialSpaceVault[C], error) {
	client := rpc.NewClient[C](conn)
	client.Logger = log.StandardLogger()

	if err := client.Initialize(ctx, credentials); err != nil {
		return nil, fmt.Errorf("(ConfidentialSpace): %w", err)
	}

	// populate from storage
	r, err := storage.GetKeys(ctx)
	if err != nil {
		return nil, fmt.Errorf("(ConfidentialSpace): %w", err)
	}

	var keys []*confidentialKey
	for k := range r.Result() {
		log.WithField("pkh", k.PublicKeyHash).Debug("Importing encrypted key")
		res, err := client.Import(ctx, k.EncryptedPrivateKey)
		if err != nil {
			return nil, fmt.Errorf("(ConfidentialSpace): %w", err)
		}
		p, err := res.PublicKey.PublicKey()
		if err != nil {
			return nil, fmt.Errorf("(ConfidentialSpace): %w", err)
		}
		keys = append(keys, &confidentialKey{
			pub:    p,
			handle: res.Handle,
		})
	}
	if err := r.Err(); err != nil {
		return nil, fmt.Errorf("(ConfidentialSpace): %w", err)
	}

	return &ConfidentialSpaceVault[C]{
		client:  client,
		storage: storage,
		keys:    keys,
	}, nil
}

///////////////////////////////////////////////////////////////////////////////////////////

func init() {
	vault.RegisterVault("confidentialspace", func(ctx context.Context, node *yaml.Node, global config.GlobalContext) (vault.Vault, error) {
		var conf *Config
		if node != nil && !node.IsZero() {
			conf = &Config{}
			if err := node.Decode(conf); err != nil {
				return nil, err
			}
		}
		return New(ctx, conf, global)
	})
}

///////////////////////////////////////////////////////////////////////////////////////////

var (
	_ vault.Importer  = (*ConfidentialSpaceVault[rpc.ConfidentialSpaceCredentials])(nil)
	_ vault.Generator = (*ConfidentialSpaceVault[rpc.ConfidentialSpaceCredentials])(nil)
)
