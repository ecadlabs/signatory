package file

import (
	"context"
	"crypto"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"sync"
	"syscall"

	config "github.com/ecadlabs/signatory/pkg/config"
	"github.com/ecadlabs/signatory/pkg/cryptoutils"
	"github.com/ecadlabs/signatory/pkg/errors"
	"github.com/ecadlabs/signatory/pkg/tezos"
	"github.com/ecadlabs/signatory/pkg/vault"
	"golang.org/x/crypto/ssh/terminal"
	"gopkg.in/yaml.v3"
)

// Config contains file based backend configuration
type Config struct {
	File string `yaml:"file" validate:"required"`
}

type secretKey string

func (k secretKey) trim() string {
	if i := strings.IndexByte(string(k), ':'); i >= 0 {
		return string(k)[i+1:]
	}
	return string(k)
}

type tezosSecretJSONEntry struct {
	Name  string    `json:"name"`
	Value secretKey `json:"value"`
}

type fileKey struct {
	privateKey cryptoutils.PrivateKey
	id         string
}

// PublicKey get the public key associated with this key
func (f *fileKey) PublicKey() crypto.PublicKey {
	return f.privateKey.Public()
}

// ID get the id of this file key
func (f *fileKey) ID() string {
	return f.id
}

// Vault is a file system based vault
type Vault struct {
	raw   []*tezosSecretJSONEntry
	keys  []*fileKey
	index map[string]*fileKey
	mtx   sync.Mutex
}

type fileIterator struct {
	keys []*fileKey
	idx  int
}

func (i *fileIterator) Next() (key vault.StoredKey, err error) {
	if i.idx == len(i.keys) {
		return nil, vault.ErrDone
	}
	key = i.keys[i.idx]
	i.idx++
	return key, nil
}

// NewVault create a new file based vault
func NewVault(ctx context.Context, config *Config) (vault *Vault, err error) {
	content, err := ioutil.ReadFile(config.File)
	if err != nil {
		return nil, fmt.Errorf("(File): %v", err)
	}

	var entries []*tezosSecretJSONEntry
	if err := json.Unmarshal(content, &entries); err != nil {
		return nil, fmt.Errorf("(File): %v", err)
	}

	return &Vault{
		raw: entries,
	}, nil
}

// ListPublicKeys list all public key available on disk
func (v *Vault) ListPublicKeys(ctx context.Context) vault.StoredKeysIterator {
	v.mtx.Lock()
	defer v.mtx.Unlock()
	return &fileIterator{keys: v.keys}
}

// GetPublicKey retrieve a public key
func (v *Vault) GetPublicKey(ctx context.Context, keyID string) (vault.StoredKey, error) {
	v.mtx.Lock()
	defer v.mtx.Unlock()
	key, ok := v.index[keyID]
	if !ok {
		return nil, errors.Wrap(fmt.Errorf("(File): key not found in vault: %s", keyID), http.StatusNotFound)
	}
	return key, nil
}

// Name returns backend name
func (v *Vault) Name() string { return "File" }

// Sign sign using the specified key
func (v *Vault) Sign(ctx context.Context, digest []byte, k vault.StoredKey) (sig cryptoutils.Signature, err error) {
	key, ok := k.(*fileKey)
	if !ok {
		return nil, errors.Wrap(fmt.Errorf("(File): invalid key type: %T ", k), http.StatusBadRequest)
	}
	signature, err := cryptoutils.Sign(key.privateKey, digest)
	if err != nil {
		return nil, fmt.Errorf("(File): %v", err)
	}
	return signature, nil
}

// Unlock unlock all encrypted keys on disk
func (v *Vault) Unlock(ctx context.Context) error {
	keys := make([]*fileKey, len(v.raw))
	index := make(map[string]*fileKey, len(v.raw))

	for i, entry := range v.raw {
		pk, err := tezos.ParsePrivateKey(entry.Value.trim(), func() ([]byte, error) {
			fmt.Printf("(File): Enter password to unlock key `%s': ", entry.Name)
			defer fmt.Println()
			return terminal.ReadPassword(int(syscall.Stdin))
		})
		if err != nil {
			return fmt.Errorf("(File): %v", err)
		}
		key := fileKey{
			privateKey: pk,
			id:         entry.Name,
		}
		keys[i] = &key
		index[key.id] = &key
	}

	v.mtx.Lock()
	defer v.mtx.Unlock()
	v.keys = keys
	v.index = index
	return nil
}

func init() {
	vault.RegisterVault("file", func(ctx context.Context, node *yaml.Node) (vault.Vault, error) {
		var conf Config
		if node == nil || node.Kind == 0 {
			return nil, errors.New("(File): config is missing")
		}
		if err := node.Decode(&conf); err != nil {
			return nil, err
		}

		if err := config.Validator().Struct(&conf); err != nil {
			return nil, err
		}

		return NewVault(ctx, &conf)
	})
}

var _ vault.Unlocker = &Vault{}
