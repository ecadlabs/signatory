package nitro

import (
	"context"
	"errors"
	"fmt"
	"iter"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	tz "github.com/ecadlabs/gotez/v2"
	"github.com/ecadlabs/gotez/v2/crypt"
	"github.com/ecadlabs/signatory/pkg/config"
	"github.com/ecadlabs/signatory/pkg/cryptoutils"
	"github.com/ecadlabs/signatory/pkg/utils"
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
	defaultAddress = "vsock://16:2000"
)

type Config struct {
	EnclaveSignerAddress string         `yaml:"enclave_signer_address"`
	Storage              *StorageConfig `yaml:"storage"`
	Credentials          *Credentials   `yaml:"credentials"`
}

type Credentials struct {
	AccessKeyID     string `yaml:"access_key_id"`
	SecretAccessKey string `yaml:"secret_access_key"`
}

type NitroVault struct {
	client  *rpc.Client
	storage keyBlobStorage
	keys    []*nitroKey
	mtx     sync.Mutex
}

type nitroKey struct {
	pub    crypt.PublicKey
	handle uint64
}

type nitroKeyRef struct {
	*nitroKey
	v *NitroVault
}

func (r *nitroKeyRef) PublicKey() crypt.PublicKey { return r.pub }
func (r *nitroKeyRef) Vault() vault.Vault         { return r.v }

func (r *nitroKeyRef) Sign(ctx context.Context, message []byte) (crypt.Signature, error) {
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

func fromEnv(value *string, name string) {
	if *value == "" {
		*value = os.Getenv(name)
	}
}

func New(ctx context.Context, conf *Config, global config.GlobalContext) (*NitroVault, error) {
	var cred rpc.Credentials
	if conf.Credentials != nil {
		cred.AccessKeyID = conf.Credentials.AccessKeyID
		cred.SecretAccessKey = conf.Credentials.SecretAccessKey
	}
	fromEnv(&cred.AccessKeyID, "NITRO_ENCLAVE_AWS_ACCESS_KEY_ID")
	fromEnv(&cred.SecretAccessKey, "NITRO_ENCLAVE_AWS_SECRET_ACCESS_KEY")

	if cred.AccessKeyID == "" || cred.SecretAccessKey == "" {
		return nil, errors.New("(Nitro): missing credentials")
	}

	var addr string
	if conf.EnclaveSignerAddress != "" {
		addr = conf.EnclaveSignerAddress
	} else {
		addr = defaultAddress
	}

	isTCP := false
	var hostport string
	if strings.Contains(addr, "//") {
		u, err := url.Parse(addr)
		if err != nil {
			return nil, fmt.Errorf("(Nitro): %w", err)
		}
		switch u.Scheme {
		case "vsock":
		case "tcp":
			isTCP = true
		default:
			return nil, fmt.Errorf("(Nitro): unknown scheme: %s", u.Scheme)
		}
		hostport = u.Host
	} else {
		hostport = addr
	}

	host, port, err := net.SplitHostPort(hostport)
	if err != nil {
		return nil, fmt.Errorf("(Nitro): %w", err)
	}

	storage, err := newStorage(ctx, conf.Storage, global)
	if err != nil {
		return nil, fmt.Errorf("(Nitro): %w", err)
	}

	log.Infof("(Nitro): connecting to the enclave signer on %s...", addr)
	var conn net.Conn
	if !isTCP {
		h, err := strconv.ParseUint(host, 0, 32)
		if err != nil {
			return nil, fmt.Errorf("(Nitro): %w", err)
		}
		p, err := strconv.ParseUint(port, 0, 32)
		if err != nil {
			return nil, fmt.Errorf("(Nitro): %w", err)
		}
		enclaveAddr := vsock.Addr{CID: uint32(h), Port: uint32(p)}

		if conn, err = vsock.Dial(&enclaveAddr); err != nil {
			return nil, fmt.Errorf("(Nitro): %w", err)
		}
	} else {
		var d net.Dialer
		if conn, err = d.DialContext(ctx, "tcp", host+":"+port); err != nil {
			return nil, fmt.Errorf("(Nitro): %w", err)
		}
	}

	client := rpc.NewClient(conn)
	if err := client.Initialize(ctx, &cred); err != nil {
		return nil, fmt.Errorf("(Nitro): %w", err)
	}

	// populate from storage
	r, err := storage.GetKeys(ctx)
	if err != nil {
		return nil, fmt.Errorf("(Nitro): %w", err)
	}

	var keys []*nitroKey
	for k := range r.Result() {
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

	return &NitroVault{
		client:  client,
		storage: storage,
		keys:    keys,
	}, nil
}

func (v *NitroVault) List(ctx context.Context) vault.KeyIterator {
	v.mtx.Lock()
	defer v.mtx.Unlock()

	snap := v.keys
	i := 0
	return vault.IteratorFunc(func() (key vault.KeyReference, err error) {
		if i >= len(snap) {
			return nil, vault.ErrDone
		}
		k := &nitroKeyRef{
			nitroKey: snap[i],
			v:        v,
		}
		i++
		return k, nil
	})
}

func (v *NitroVault) Import(ctx context.Context, pk crypt.PrivateKey, opt utils.Options) (vault.KeyReference, error) {
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

	return &nitroKeyRef{
		nitroKey: key,
		v:        v,
	}, nil
}

func (v *NitroVault) Generate(ctx context.Context, keyType *cryptoutils.KeyType, n int) (vault.KeyIterator, error) {
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
		k := &nitroKeyRef{
			nitroKey: imported[i],
			v:        v,
		}
		i++
		return k, nil
	}), nil
}

func (v *NitroVault) Close(ctx context.Context) error {
	return v.client.Close()
}

func (v *NitroVault) Name() string { return "NitroEnclave" }

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
	_ vault.Importer  = (*NitroVault)(nil)
	_ vault.Generator = (*NitroVault)(nil)
)
