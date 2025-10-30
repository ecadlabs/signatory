package sgx

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
	awsutils "github.com/ecadlabs/signatory/pkg/utils/aws"
	"github.com/ecadlabs/signatory/pkg/vault"
	"github.com/ecadlabs/signatory/pkg/vault/sgx/rpc"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
)

const (
	DefaultCID       = 16
	DefaultPort      = 2000
	DefaultProxyPort = 8000
)

const defaultFile = "sgx_keys.json"

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
	SGXHost            string         `yaml:"host"`
	SGXPort            string         `yaml:"port"`
	EncryptionKeyID    string         `yaml:"encryption_key_id"`
	ProxyPort          *uint32        `yaml:"proxy_local_port"`
	ProxyRemoteAddress string         `yaml:"proxy_remote_address"`
	Storage            *StorageConfig `yaml:"storage"`
	Credentials        *Credentials   `yaml:"credentials"`
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

func resolvePtr[T any](value *T, ev string) *T {
	if value == nil {
		if env := os.Getenv(ev); env != "" {
			var tmp T
			if _, err := fmt.Sscanf(env, "%v", &tmp); err == nil {
				return &tmp
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
		SGXHost:            resolve(c.SGXHost, "SGX_HOST"),
		SGXPort:            resolve(c.SGXPort, "SGX_PORT"),
		EncryptionKeyID:    resolve(c.EncryptionKeyID, "ENCRYPTION_KEY_ID"),
		ProxyPort:          resolvePtr(c.ProxyPort, "PROXY_LOCAL_PORT"),
		ProxyRemoteAddress: resolve(c.ProxyRemoteAddress, "PROXY_REMOTE_ADDRESS"),
		Storage:            c.Storage,
		Credentials:        c.Credentials,
	}
}

type Credentials = awsutils.Config

type SgxVault[C any] struct {
	client  *rpc.Client[C]
	storage keyBlobStorage
	keys    []*sgxKey
	mtx     sync.Mutex
}

type sgxKey struct {
	pub    crypt.PublicKey
	handle uint64
}

type sgxKeyRef[C any] struct {
	*sgxKey
	v *SgxVault[C]
}

func (r *sgxKeyRef[C]) PublicKey() crypt.PublicKey { return r.pub }
func (r *sgxKeyRef[C]) Vault() vault.Vault         { return r.v }

func (r *sgxKeyRef[C]) Sign(ctx context.Context, message []byte, opt *vault.SignOptions) (crypt.Signature, error) {
	r.v.mtx.Lock()
	defer r.v.mtx.Unlock()

	sig, err := r.v.client.Sign(ctx, r.handle, message, opt)
	if err != nil {
		return nil, fmt.Errorf("(SGX): %w", err)
	}

	res, err := sig.Signature()
	if err != nil {
		return nil, fmt.Errorf("(SGX): %w", err)
	}
	return res, nil
}

func (r *sgxKeyRef[C]) ProvePossession(ctx context.Context) (crypt.Signature, error) {
	r.v.mtx.Lock()
	defer r.v.mtx.Unlock()

	sig, err := r.v.client.ProvePossession(ctx, r.handle)
	if err != nil {
		return nil, fmt.Errorf("(SGX): %w", err)
	}

	res, err := sig.Signature()
	if err != nil {
		return nil, fmt.Errorf("(SGX): %w", err)
	}
	return res, nil
}

func New(ctx context.Context, config *Config, global config.GlobalContext) (*SgxVault[rpc.AWSCredentials], error) {
	var sc *StorageConfig
	if config != nil {
		sc = config.Storage
	}
	storage, err := newStorage(ctx, sc, global)
	if err != nil {
		return nil, fmt.Errorf("(SGX): %w", err)
	}
	return newWithStorage(ctx, config, storage)
}

func newWithStorage(ctx context.Context, config *Config, storage keyBlobStorage) (*SgxVault[rpc.AWSCredentials], error) {
	conf := populateConfig(config)
	var tmp awsutils.ConfigProvider
	if conf.Credentials != nil {
		// nil pointer passed as an interface is not a nil interface!
		tmp = conf.Credentials
	}
	rpcCred, err := rpc.LoadAWSCredentials(ctx, tmp)
	if err != nil {
		return nil, fmt.Errorf("(SGX): %w", err)
	}
	rpcCred.EncryptionKeyID = conf.EncryptionKeyID

	if rpcCred.EncryptionKeyID == "" {
		return nil, errors.New("(SGX): missing encryption key id")
	}
	if !rpcCred.IsValid() {
		return nil, errors.New("(SGX): missing credentials")
	}

	if conf.SGXHost == "" {
		return nil, errors.New("(SGX): missing SGX host")
	}

	if conf.SGXPort == "" {
		return nil, errors.New("(SGX): missing SGX port")
	}

	addr := net.JoinHostPort(conf.SGXHost, conf.SGXPort)
	log.Infof("(SGX): connecting to the enclave signer on %v...", addr)
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("(SGX): %w", err)
	}

	v, err := newWithConn(ctx, conn, rpcCred, storage)
	if err != nil {
		return nil, err
	}
	return v, nil
}

func newWithConn[C any](ctx context.Context, conn net.Conn, credentials *C, storage keyBlobStorage) (*SgxVault[C], error) {
	client := rpc.NewClient[C](conn)
	client.Logger = log.StandardLogger()

	if err := client.Initialize(ctx, credentials); err != nil {
		return nil, fmt.Errorf("(SGX): %w", err)
	}

	// populate from storage
	r, err := storage.GetKeys(ctx)
	if err != nil {
		return nil, fmt.Errorf("(SGX): %w", err)
	}

	var keys []*sgxKey
	for k := range r.Result() {
		log.WithField("pkh", k.PublicKeyHash).Debug("Importing encrypted key")
		res, err := client.Import(ctx, k.EncryptedPrivateKey)
		if err != nil {
			return nil, fmt.Errorf("(SGX): %w", err)
		}
		p, err := res.PublicKey.PublicKey()
		if err != nil {
			return nil, fmt.Errorf("(SGX): %w", err)
		}
		keys = append(keys, &sgxKey{
			pub:    p,
			handle: res.Handle,
		})
	}
	if err := r.Err(); err != nil {
		return nil, fmt.Errorf("(SGX): %w", err)
	}

	return &SgxVault[C]{
		client:  client,
		storage: storage,
		keys:    keys,
	}, nil
}

func (v *SgxVault[C]) List(ctx context.Context) vault.KeyIterator {
	v.mtx.Lock()
	defer v.mtx.Unlock()

	snap := v.keys
	i := 0
	return vault.IteratorFunc(func() (key vault.KeyReference, err error) {
		if i >= len(snap) {
			return nil, vault.ErrDone
		}
		k := &sgxKeyRef[C]{
			sgxKey: snap[i],
			v:      v,
		}
		i++
		return k, nil
	})
}

func (v *SgxVault[C]) Import(ctx context.Context, pk crypt.PrivateKey, opt utils.Options) (vault.KeyReference, error) {
	rpcPk, err := rpc.NewPrivateKey(pk)
	if err != nil {
		return nil, fmt.Errorf("(SGX): %w", err)
	}

	v.mtx.Lock()
	defer v.mtx.Unlock()

	res, err := v.client.ImportUnencrypted(ctx, rpcPk)
	if err != nil {
		return nil, fmt.Errorf("(SGX): %w", err)
	}
	p, err := res.PublicKey.PublicKey()
	if err != nil {
		return nil, fmt.Errorf("(SGX): %w", err)
	}
	key := &sgxKey{
		pub:    p,
		handle: res.Handle,
	}
	v.keys = append(v.keys, key)

	if err := v.storage.ImportKey(ctx, &encryptedKey{
		PublicKeyHash:       p.Hash(),
		EncryptedPrivateKey: res.EncryptedPrivateKey,
	}); err != nil {
		return nil, fmt.Errorf("(SGX): %w", err)
	}

	return &sgxKeyRef[C]{
		sgxKey: key,
		v:      v,
	}, nil
}

func (v *SgxVault[C]) Generate(ctx context.Context, keyType *cryptoutils.KeyType, n int) (vault.KeyIterator, error) {
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
		return nil, fmt.Errorf("(SGX): unsupported key type %v", keyType)
	}

	v.mtx.Lock()
	defer v.mtx.Unlock()

	var imported []*sgxKey
	for i := 0; i < n; i++ {
		res, err := v.client.GenerateAndImport(ctx, kt)
		if err != nil {
			return nil, fmt.Errorf("(SGX): %w", err)
		}
		p, err := res.PublicKey.PublicKey()
		if err != nil {
			return nil, fmt.Errorf("(SGX): %w", err)
		}
		key := &sgxKey{
			pub:    p,
			handle: res.Handle,
		}
		v.keys = append(v.keys, key)
		if err := v.storage.ImportKey(ctx, &encryptedKey{
			PublicKeyHash:       p.Hash(),
			EncryptedPrivateKey: res.EncryptedPrivateKey,
		}); err != nil {
			return nil, fmt.Errorf("(SGX): %w", err)
		}
		imported = append(imported, key)
	}

	i := 0
	return vault.IteratorFunc(func() (key vault.KeyReference, err error) {
		if i >= len(imported) {
			return nil, vault.ErrDone
		}
		k := &sgxKeyRef[C]{
			sgxKey: imported[i],
			v:      v,
		}
		i++
		return k, nil
	}), nil
}

func (v *SgxVault[C]) Close(ctx context.Context) (err error) {
	err = v.client.Close()
	return err
}

func (v *SgxVault[C]) Name() string { return "IntelSGX" }

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
		// case "aws", "dynamodb":
		// 	var cfg awsStorageConfig
		// 	if !conf.Config.IsZero() {
		// 		if err := conf.Config.Decode(&cfg); err != nil {
		// 			return nil, err
		// 		}
		// 	}
		// 	return newAWSStorage(ctx, &cfg)
		default:
			return nil, fmt.Errorf("(SGX): unknown key storage %s", conf.Driver)
		}
	} else {
		path := filepath.Join(global.GetBaseDir(), defaultFile)
		return newFileStorage(path)
	}
}

func init() {
	vault.RegisterVault("sgx", func(ctx context.Context, node *yaml.Node, global config.GlobalContext) (vault.Vault, error) {
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

var (
	_ vault.Importer  = (*SgxVault[rpc.AWSCredentials])(nil)
	_ vault.Generator = (*SgxVault[rpc.AWSCredentials])(nil)
)
