package nitro

import (
	"context"
	"errors"
	"fmt"
	"iter"
	"net"
	"path/filepath"
	"sync"

	tz "github.com/ecadlabs/gotez/v2"
	"github.com/ecadlabs/gotez/v2/crypt"
	"github.com/ecadlabs/signatory/pkg/config"
	"github.com/ecadlabs/signatory/pkg/cryptoutils"
	"github.com/ecadlabs/signatory/pkg/utils"
	awsutils "github.com/ecadlabs/signatory/pkg/utils/aws"
	"github.com/ecadlabs/signatory/pkg/vault"
	"github.com/ecadlabs/signatory/pkg/vault/nitro/rpc"
	"github.com/ecadlabs/signatory/pkg/vault/nitro/rpc/vsock"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
)

type StorageConfig struct {
	Driver string    `yaml:"driver"`
	Config yaml.Node `yaml:"config"`
}

type encryptedKey struct {
	PublicKeyHash       tz.PublicKeyHash `json:"public_key_hash"`
	EncryptedPrivateKey []byte           `json:"encrypted_private_key"`
}

type result[T any] interface {
	Result() iter.Seq[T]
	Err() error
}

type keyBlobStorage interface {
	GetKeys(ctx context.Context) (result[*encryptedKey], error)
	ImportKey(ctx context.Context, encryptedKey *encryptedKey) error
}

const (
	DefaultCID  = 16
	DefaultPort = 2000
)

type Config struct {
	EnclaveCID      *uint32        `yaml:"enclave_cid"`
	EnclavePort     *uint32        `yaml:"enclave_port"`
	EncryptionKeyID string         `yaml:"encryption_key_id"`
	Storage         *StorageConfig `yaml:"storage"`
	Credentials     *Credentials   `yaml:"credentials"`
}

type Credentials struct {
	AccessKeyID     string `yaml:"access_key_id"`
	SecretAccessKey string `yaml:"secret_access_key"`
	SessionToken    string `yaml:"session_token"`
}

func (c *Credentials) GetAccessKeyID() string     { return c.AccessKeyID }
func (c *Credentials) GetSecretAccessKey() string { return c.SecretAccessKey }
func (c *Credentials) GetSessionToken() string    { return c.SessionToken }

type NitroVault[C any] struct {
	client  *rpc.Client[C]
	storage keyBlobStorage
	keys    []*nitroKey
	mtx     sync.Mutex
}

type nitroKey struct {
	pub    crypt.PublicKey
	handle uint64
}

type nitroKeyRef[C any] struct {
	*nitroKey
	v *NitroVault[C]
}

func (r *nitroKeyRef[C]) PublicKey() crypt.PublicKey { return r.pub }
func (r *nitroKeyRef[C]) Vault() vault.Vault         { return r.v }

func (r *nitroKeyRef[C]) Sign(ctx context.Context, message []byte) (crypt.Signature, error) {
	r.v.mtx.Lock()
	defer r.v.mtx.Unlock()

	sig, err := r.v.client.Sign(ctx, r.handle, message)
	if err != nil {
		return nil, fmt.Errorf("(Nitro): %w", err)
	}

	res, err := sig.Signature()
	if err != nil {
		return nil, fmt.Errorf("(Nitro): %w", err)
	}
	return res, nil
}

func New(ctx context.Context, conf *Config, global config.GlobalContext) (*NitroVault[rpc.AWSCredentials], error) {
	var tmp awsutils.ConfigProvider
	if conf.Credentials != nil {
		tmp = conf.Credentials
	}
	rpcCred, err := rpc.LoadAWSCredentials(ctx, tmp)
	if err != nil {
		return nil, fmt.Errorf("(Nitro): %w", err)
	}

	cid := uint32(DefaultCID)
	port := uint32(DefaultPort)
	if conf.EnclaveCID != nil {
		cid = *conf.EnclaveCID
	}
	if conf.EnclavePort != nil {
		port = *conf.EnclavePort
	}

	storage, err := newStorage(ctx, conf.Storage, global)
	if err != nil {
		return nil, fmt.Errorf("(Nitro): %w", err)
	}

	addr := vsock.Addr{CID: cid, Port: port}
	log.Infof("(Nitro): connecting to the enclave signer on %v...", &addr)
	conn, err := vsock.Dial(&addr)
	if err != nil {
		return nil, fmt.Errorf("(Nitro): %w", err)
	}
	return newWithConn(ctx, conn, rpcCred, storage)
}

func newWithConn[C any](ctx context.Context, conn net.Conn, credentials *C, storage keyBlobStorage) (*NitroVault[C], error) {
	client := rpc.NewClient[C](conn, nil)
	if err := client.Initialize(ctx, credentials); err != nil {
		return nil, fmt.Errorf("(Nitro): %w", err)
	}

	// populate from storage
	r, err := storage.GetKeys(ctx)
	if err != nil {
		return nil, fmt.Errorf("(Nitro): %w", err)
	}

	var keys []*nitroKey
	for k := range r.Result() {
		log.WithField("pkh", k.PublicKeyHash).Debug("Importing encrypted key")
		pub, handle, err := client.Import(ctx, k.EncryptedPrivateKey)
		if err != nil {
			return nil, fmt.Errorf("(Nitro): %w", err)
		}
		p, err := pub.PublicKey()
		if err != nil {
			return nil, fmt.Errorf("(Nitro): %w", err)
		}
		keys = append(keys, &nitroKey{
			pub:    p,
			handle: handle,
		})
	}
	if err := r.Err(); err != nil {
		return nil, fmt.Errorf("(Nitro): %w", err)
	}

	return &NitroVault[C]{
		client:  client,
		storage: storage,
		keys:    keys,
	}, nil
}

func (v *NitroVault[C]) List(ctx context.Context) vault.KeyIterator {
	v.mtx.Lock()
	defer v.mtx.Unlock()

	snap := v.keys
	i := 0
	return vault.IteratorFunc(func() (key vault.KeyReference, err error) {
		if i >= len(snap) {
			return nil, vault.ErrDone
		}
		k := &nitroKeyRef[C]{
			nitroKey: snap[i],
			v:        v,
		}
		i++
		return k, nil
	})
}

func (v *NitroVault[C]) Import(ctx context.Context, pk crypt.PrivateKey, opt utils.Options) (vault.KeyReference, error) {
	rpcPk, err := rpc.NewPrivateKey(pk)
	if err != nil {
		return nil, fmt.Errorf("(Nitro): %w", err)
	}

	v.mtx.Lock()
	defer v.mtx.Unlock()

	data, pub, handle, err := v.client.ImportUnencrypted(ctx, rpcPk)
	if err != nil {
		return nil, fmt.Errorf("(Nitro): %w", err)
	}
	p, err := pub.PublicKey()
	if err != nil {
		return nil, fmt.Errorf("(Nitro): %w", err)
	}
	key := &nitroKey{
		pub:    p,
		handle: handle,
	}
	v.keys = append(v.keys, key)

	if err := v.storage.ImportKey(ctx, &encryptedKey{
		PublicKeyHash:       p.Hash(),
		EncryptedPrivateKey: data,
	}); err != nil {
		return nil, fmt.Errorf("(Nitro): %w", err)
	}

	return &nitroKeyRef[C]{
		nitroKey: key,
		v:        v,
	}, nil
}

func (v *NitroVault[C]) Generate(ctx context.Context, keyType *cryptoutils.KeyType, n int) (vault.KeyIterator, error) {
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
		return nil, fmt.Errorf("(Nitro): unsupported key type %v", keyType)
	}

	v.mtx.Lock()
	defer v.mtx.Unlock()

	var imported []*nitroKey
	for i := 0; i < n; i++ {
		data, pub, handle, err := v.client.GenerateAndImport(ctx, kt)
		if err != nil {
			return nil, fmt.Errorf("(Nitro): %w", err)
		}
		p, err := pub.PublicKey()
		if err != nil {
			return nil, fmt.Errorf("(Nitro): %w", err)
		}
		key := &nitroKey{
			pub:    p,
			handle: handle,
		}
		v.keys = append(v.keys, key)
		if err := v.storage.ImportKey(ctx, &encryptedKey{
			PublicKeyHash:       p.Hash(),
			EncryptedPrivateKey: data,
		}); err != nil {
			return nil, fmt.Errorf("(Nitro): %w", err)
		}
		imported = append(imported, key)
	}

	i := 0
	return vault.IteratorFunc(func() (key vault.KeyReference, err error) {
		if i >= len(imported) {
			return nil, vault.ErrDone
		}
		k := &nitroKeyRef[C]{
			nitroKey: imported[i],
			v:        v,
		}
		i++
		return k, nil
	}), nil
}

func (v *NitroVault[C]) Close(context.Context) error {
	return v.client.Close()
}

func (v *NitroVault[C]) Name() string { return "NitroEnclave" }

const defaultFile = "enclave_keys.json"

func newStorage(ctx context.Context, conf *StorageConfig, global config.GlobalContext) (keyBlobStorage, error) {
	if conf != nil {
		switch conf.Driver {
		case "file":
			var path string
			if conf.Config.IsZero() {
				path = filepath.Join(global.GetBaseDir(), defaultFile)
			} else if err := conf.Config.Decode(&path); err != nil {
				return nil, err
			}
			return newFileStorage(path)
		case "aws", "dynamodb":
			var cfg awsStorageConfig
			if err := conf.Config.Decode(&cfg); err != nil {
				return nil, err
			}
			return newAWSStorage(ctx, &cfg)
		default:
			return nil, fmt.Errorf("unknown key storage %s", conf.Driver)
		}
	} else {
		path := filepath.Join(global.GetBaseDir(), defaultFile)
		return newFileStorage(path)
	}
}

func init() {
	vault.RegisterVault("nitro", func(ctx context.Context, node *yaml.Node, global config.GlobalContext) (vault.Vault, error) {
		var conf Config
		if node == nil || node.Kind == 0 {
			return nil, errors.New("(Nitro): config is missing")
		}
		if err := node.Decode(&conf); err != nil {
			return nil, err
		}
		return New(ctx, &conf, global)
	})
}

var (
	_ vault.Importer  = (*NitroVault[rpc.AWSCredentials])(nil)
	_ vault.Generator = (*NitroVault[rpc.AWSCredentials])(nil)
)
