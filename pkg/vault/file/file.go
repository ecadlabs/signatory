package file

import (
	"context"
	"crypto"
	"encoding/json"
	"fmt"
	config "github.com/ecadlabs/signatory/pkg/config"
	"github.com/ecadlabs/signatory/pkg/cryptoutils"
	"github.com/ecadlabs/signatory/pkg/errors"
	"github.com/ecadlabs/signatory/pkg/tezos"
	"github.com/ecadlabs/signatory/pkg/vault"
	"golang.org/x/crypto/ssh/terminal"
	"gopkg.in/yaml.v3"
	"io/ioutil"
	"strings"
	"syscall"
)

const (
	ENCRYPTED   = "encrypted"
	UNENCRYPTED = "unencrypted"
	UNKNOWN     = "unknown"
)

// Config contains Google Cloud KMS backend configuration
type Config struct {
	File  string `yaml:"file"`
	Vault string `yaml:"vault"`
}

type secretKey string

func (k secretKey) scheme() string {
	if strings.HasPrefix(string(k), "encrypted") {
		return ENCRYPTED
	} else if strings.HasPrefix(string(k), "unencrypted") {
		return UNENCRYPTED
	} else {
		return UNKNOWN
	}
}

func (k secretKey) toKey(passphrase []byte) (cryptoutils.PrivateKey, error) {
	passCB := func() ([]byte, error) {
		return passphrase, nil
	}
	if k.scheme() == ENCRYPTED {
		return tezos.ParsePrivateKey(strings.TrimPrefix(string(k), "encrypted:"), passCB)
	} else if k.scheme() == UNENCRYPTED {
		return tezos.ParsePrivateKey(strings.TrimPrefix(string(k), "unencrypted:"), passCB)
	}

	return nil, fmt.Errorf("Unsupported key type")
}

type tezosSecretJSONEntry struct {
	Name       string    `json:"name"`
	Value      secretKey `json:"value"`
	passphrase []byte
}

type fileKeys struct {
	privateKey cryptoutils.PrivateKey
	id         string
}

// PublicKey get the public key associated with this key
func (f *fileKeys) PublicKey() crypto.PublicKey {
	return f.privateKey.Public()
}

// ID get the id of this file key
func (f *fileKeys) ID() string {
	return f.id
}

func (f *tezosSecretJSONEntry) unlocked() bool {
	if f.Value.scheme() == UNKNOWN {
		return false
	}

	if f.Value.scheme() == ENCRYPTED && (len(f.passphrase) == 0 || f.passphrase == nil) {
		return false
	}
	return true
}

func (f *tezosSecretJSONEntry) unlock(passFunc func() ([]byte, error)) error {
	pass, err := passFunc()
	if err != nil {
		return err
	}

	f.passphrase = pass
	_, err = f.Value.toKey(f.passphrase)
	return err
}

func (f *tezosSecretJSONEntry) key() (*fileKeys, error) {
	k, err := f.Value.toKey(f.passphrase)

	if err != nil {
		return nil, err
	}

	return &fileKeys{
		id:         f.Name,
		privateKey: k,
	}, nil
}

// Vault is a file system based vault
type Vault struct {
	config Config
	keys   map[string]*tezosSecretJSONEntry
}

type fileIterator struct {
	v    *Vault
	i    int
	keys []string
	done bool
}

func (i *fileIterator) Next() (key vault.StoredKey, err error) {
	if i.done {
		return nil, vault.ErrDone
	}

	defer func() {
		i.i++
		if i.i == len(i.keys) {
			i.done = true
		}
	}()

	return i.v.keys[i.keys[i.i]].key()
}

// NewVault create a new file based vault
func NewVault(ctx context.Context, config *Config) (vault *Vault, err error) {
	content, err := ioutil.ReadFile(config.File)

	if err != nil {
		return nil, err
	}

	entries := []*tezosSecretJSONEntry{}
	json.Unmarshal([]byte(content), &entries)

	keys := make(map[string]*tezosSecretJSONEntry)

	for _, entry := range entries {
		if entry.Value.scheme() == UNKNOWN {
			continue
		}

		keys[entry.Name] = entry
	}

	return &Vault{
		config: *config,
		keys:   keys,
	}, nil
}

// ListPublicKeys list all public key available on disk
func (v *Vault) ListPublicKeys(ctx context.Context) vault.StoredKeysIterator {
	keys := []string{}
	for k := range v.keys {
		keys = append(keys, k)
	}
	return &fileIterator{
		v:    v,
		i:    0,
		done: len(keys) == 0,
		keys: keys,
	}
}

// GetPublicKey retrieve a public key
func (v *Vault) GetPublicKey(ctx context.Context, keyID string) (vault.StoredKey, error) {
	key, ok := v.keys[keyID]
	if !ok {
		return nil, errors.New("Key ID not found in vault")
	}

	return key.key()
}

// Name returns backend name
func (v *Vault) Name() string {
	return "File"
}

// VaultName returns vault name
func (v *Vault) VaultName() string {
	return v.config.Vault
}

// Sign sign using the specified key
func (v *Vault) Sign(ctx context.Context, digest []byte, key vault.StoredKey) (sig cryptoutils.Signature, err error) {
	if k, ok := key.(*fileKeys); ok {
		signature, err := cryptoutils.Sign(k.privateKey, digest)
		if err != nil {
			return nil, err
		}
		return signature, nil
	}

	return nil, errors.New("(File): Invalid key type")
}

// Unlock unlock all encrypted keys on disk
func (v *Vault) Unlock(ctx context.Context) error {
	for _, e := range v.keys {
		if e.Value.scheme() == ENCRYPTED {
			passCB := func() ([]byte, error) {
				fmt.Printf("Enter Password for %s from Vault (%s):", e.Name, v.Name())
				defer fmt.Println()
				return terminal.ReadPassword(int(syscall.Stdin))
			}
			if err := e.unlock(passCB); err != nil {
				return err
			}
		}
	}

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
