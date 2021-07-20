package memory

import (
	"context"
	"crypto"
	"fmt"
	"net/http"
	"sync"
	"syscall"

	"github.com/ecadlabs/signatory/pkg/cryptoutils"
	"github.com/ecadlabs/signatory/pkg/errors"
	"github.com/ecadlabs/signatory/pkg/tezos"
	"github.com/ecadlabs/signatory/pkg/vault"
	"golang.org/x/crypto/ssh/terminal"
)

type memKey struct {
	privateKey cryptoutils.PrivateKey
	id         string
}

// PublicKey get the public key associated with this key
func (f *memKey) PublicKey() crypto.PublicKey {
	return f.privateKey.Public()
}

// ID get the id of this file key
func (f *memKey) ID() string {
	return f.id
}

type KeyData struct {
	Data string
	ID   string
}

// Vault is a file system based vault
type Vault struct {
	raw   []*KeyData
	keys  []*memKey
	index map[string]*memKey
	mtx   sync.Mutex
	name  string
}

type iterator struct {
	keys []*memKey
	idx  int
}

func (i *iterator) Next() (key vault.StoredKey, err error) {
	if i.idx == len(i.keys) {
		return nil, vault.ErrDone
	}
	key = i.keys[i.idx]
	i.idx++
	return key, nil
}

// New create a new file based vault
func New(data []*KeyData, name string) *Vault {
	return &Vault{
		raw:  data,
		name: name,
	}
}

// ListPublicKeys list all public key available on disk
func (v *Vault) ListPublicKeys(ctx context.Context) vault.StoredKeysIterator {
	v.mtx.Lock()
	defer v.mtx.Unlock()
	return &iterator{keys: v.keys}
}

// GetPublicKey retrieve a public key
func (v *Vault) GetPublicKey(ctx context.Context, keyID string) (vault.StoredKey, error) {
	v.mtx.Lock()
	defer v.mtx.Unlock()
	key, ok := v.index[keyID]
	if !ok {
		return nil, errors.Wrap(fmt.Errorf("(%s): key not found in vault: %s", v.name, keyID), http.StatusNotFound)
	}
	return key, nil
}

// Name returns backend name
func (v *Vault) Name() string { return v.name }

// Sign sign using the specified key
func (v *Vault) Sign(ctx context.Context, digest []byte, k vault.StoredKey) (sig cryptoutils.Signature, err error) {
	key, ok := k.(*memKey)
	if !ok {
		return nil, errors.Wrap(fmt.Errorf("(%s): invalid key type: %T ", v.name, k), http.StatusBadRequest)
	}
	signature, err := cryptoutils.Sign(key.privateKey, digest)
	if err != nil {
		return nil, fmt.Errorf("(%s): %v", v.name, err)
	}
	return signature, nil
}

// Unlock unlock all encrypted keys on disk
func (v *Vault) Unlock(ctx context.Context) error {
	keys := make([]*memKey, len(v.raw))
	index := make(map[string]*memKey, len(v.raw))

	for i, entry := range v.raw {
		pk, err := tezos.ParsePrivateKey(entry.Data, func() ([]byte, error) {
			id := entry.ID
			if id == "" {
				id = "<unnamed>"
			}
			fmt.Printf("(%s): Enter password to unlock key `%s': ", v.name, id)
			defer fmt.Println()
			return terminal.ReadPassword(int(syscall.Stdin))
		})
		if err != nil {
			return fmt.Errorf("(%s): %v", v.name, err)
		}

		id := entry.ID
		if id == "" {
			id, err = tezos.EncodePublicKeyHash(pk.Public())
			if err != nil {
				return fmt.Errorf("(%s): %v", v.name, err)
			}
		}
		key := memKey{
			privateKey: pk,
			id:         id,
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

var _ vault.Unlocker = (*Vault)(nil)
