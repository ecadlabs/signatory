package nitro

import (
	"context"
	"errors"
	"fmt"
	"iter"
	"os"
	"sync"

	"github.com/ecadlabs/gotez/v2/crypt"
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

type Result[T any] interface {
	Result() iter.Seq[T]
	Err() error
}

type keyBlobStorage interface {
	GetKeys(ctx context.Context) (Result[[]byte], error)
	ImportKey(ctx context.Context, encryptedKeyData []byte) error
}

const (
	defaultCID  = 16
	defaultPort = 2000
)

type Config struct {
	EnclaveSignerCID  *uint32       `yaml:"enclave_signer_cid"`
	EnclaveSignerPort *uint32       `yaml:"enclave_signer_port"`
	Storage           StorageConfig `yaml:"storage"`
	Credentials       *Credentials  `yaml:"credentials"`
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

func New(ctx context.Context, conf *Config) (*NitroVault, error) {
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

	var cid, port uint32
	if conf.EnclaveSignerCID != nil {
		cid = *conf.EnclaveSignerCID
	} else {
		cid = defaultCID
	}
	if conf.EnclaveSignerPort != nil {
		port = *conf.EnclaveSignerPort
	} else {
		port = defaultPort
	}

	storage, err := newStorage(&conf.Storage)
	if err != nil {
		return nil, fmt.Errorf("(Nitro): %w", err)
	}

	enclaveAddr := vsock.Addr{CID: cid, Port: port}
	log.Infof("(Nitro): connecting to the enclave signer on %v...", &enclaveAddr)

	conn, err := vsock.Dial(&enclaveAddr)
	if err != nil {
		return nil, fmt.Errorf("(Nitro): %w", err)
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
		pub, handle, err := client.Import(ctx, k)
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
	if err := v.storage.ImportKey(ctx, data); err != nil {
		return nil, fmt.Errorf("(Nitro): %w", err)
	}

	return &nitroKeyRef{
		nitroKey: key,
		v:        v,
	}, nil
}

func (v *NitroVault) Generate(ctx context.Context, keyType *vault.KeyType, n int) (vault.KeyIterator, error) {
	var kt rpc.KeyType
	switch keyType {
	case vault.KeyEd25519:
		kt = rpc.KeyEd25519
	case vault.KeySecp256k1:
		kt = rpc.KeySecp256k1
	case vault.KeyP256:
		kt = rpc.KeyNISTP256
	case vault.KeyBLS12_381:
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
		if err := v.storage.ImportKey(ctx, data); err != nil {
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

func newStorage(conf *StorageConfig) (keyBlobStorage, error) {
	switch conf.Driver {
	case "file":
		var path string
		if err := conf.Config.Decode(&path); err != nil {
			return nil, err
		}
		storage, err := newFileStorage(path)
		if err != nil {
			return nil, err
		}
		return storage, nil
	default:
		return nil, fmt.Errorf("unknown key storage %s", conf.Driver)
	}
}

var (
	_ vault.Importer  = (*NitroVault)(nil)
	_ vault.Generator = (*NitroVault)(nil)
)
