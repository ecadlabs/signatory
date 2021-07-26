// Package memory provides a basis for file based and in-memory vaults
package memory

import (
	"context"
	"crypto"
	"fmt"
	"net/http"
	"sync"

	"github.com/ecadlabs/signatory/pkg/cryptoutils"
	"github.com/ecadlabs/signatory/pkg/errors"
	"github.com/ecadlabs/signatory/pkg/tezos"
	"github.com/ecadlabs/signatory/pkg/utils"
	"github.com/ecadlabs/signatory/pkg/vault"
)

type PrivateKey struct {
	PrivateKey cryptoutils.PrivateKey
	KeyID      string
}

// PublicKey get the public key associated with this key
func (f *PrivateKey) PublicKey() crypto.PublicKey {
	return f.PrivateKey.Public()
}

// ID get the id of this file key
func (f *PrivateKey) ID() string {
	return f.KeyID
}

type UnparsedKey struct {
	Data string
	ID   string
}

// Vault is a file system based vault
type Vault struct {
	raw      []*UnparsedKey
	keys     []*PrivateKey
	index    map[string]*PrivateKey
	mtx      sync.Mutex
	name     string
	unlocked bool
}

type iterator struct {
	keys []*PrivateKey
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

// NewUnparsed create a new in-mempory vault from Tezos encoded data. Call Unlock before use
func NewUnparsed(data []*UnparsedKey, name string) *Vault {
	if name == "" {
		name = "Mem"
	}
	return &Vault{
		raw:  data,
		name: name,
	}
}

// New create a new in-mempory vault. Call Unlock before use
func New(src []*PrivateKey, name string) (*Vault, error) {
	if name == "" {
		name = "Mem"
	}

	keys := make([]*PrivateKey, len(src))
	index := make(map[string]*PrivateKey, len(src))

	for i, k := range src {
		var key *PrivateKey
		if k.KeyID != "" {
			key = k
		} else {
			id := k.KeyID
			var err error
			if id == "" {
				id, err = tezos.EncodePublicKeyHash(k.PrivateKey.Public())
				if err != nil {
					return nil, fmt.Errorf("(%s): %v", name, err)
				}
			}
			key = &PrivateKey{
				PrivateKey: k.PrivateKey,
				KeyID:      id,
			}
		}
		keys[i] = k
		index[key.KeyID] = k
	}

	return &Vault{
		name:  name,
		keys:  keys,
		index: index,
	}, nil
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
	key, ok := k.(*PrivateKey)
	if !ok {
		return nil, errors.Wrap(fmt.Errorf("(%s): invalid key type: %T ", v.name, k), http.StatusBadRequest)
	}
	signature, err := cryptoutils.Sign(key.PrivateKey, digest)
	if err != nil {
		return nil, fmt.Errorf("(%s): %v", v.name, err)
	}
	return signature, nil
}

// Unlock unlock all encrypted keys on disk
func (v *Vault) Unlock(ctx context.Context) error {
	v.mtx.Lock()
	if v.unlocked {
		v.mtx.Unlock()
		return nil
	}
	v.mtx.Unlock()

	keys := make([]*PrivateKey, len(v.raw))
	index := make(map[string]*PrivateKey, len(v.raw))

	for i, entry := range v.raw {
		name := entry.ID
		if name == "" {
			name = "<unnamed>"
		}

		pk, err := tezos.ParsePrivateKey(entry.Data, utils.KeyboardInteractivePassphraseFunc(fmt.Sprintf("(%s): Enter password to unlock key `%s': ", v.name, name)))
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
		key := PrivateKey{
			PrivateKey: pk,
			KeyID:      id,
		}
		keys[i] = &key
		index[key.KeyID] = &key
	}

	v.mtx.Lock()
	defer v.mtx.Unlock()

	v.keys = keys
	v.index = index
	v.unlocked = true

	return nil
}

func (v *Vault) ImportKey(ctx context.Context, pk cryptoutils.PrivateKey, opt utils.Options) (vault.StoredKey, error) {
	id, ok, err := opt.GetString("name")
	if err != nil {
		return nil, fmt.Errorf("(%s): %v", v.name, err)
	}

	if !ok || id == "" {
		id, err = tezos.EncodePublicKeyHash(pk.Public())
		if err != nil {
			return nil, fmt.Errorf("(%s): %v", v.name, err)
		}
	}
	key := PrivateKey{
		PrivateKey: pk,
		KeyID:      id,
	}

	v.mtx.Lock()
	defer v.mtx.Unlock()
	v.keys = append(v.keys, &key)
	v.index[key.KeyID] = &key

	return &key, nil
}

type Importer struct {
	*Vault
}

func (i *Importer) Import(ctx context.Context, pk cryptoutils.PrivateKey, opt utils.Options) (vault.StoredKey, error) {
	return i.ImportKey(ctx, pk, opt)
}

var _ vault.Unlocker = (*Vault)(nil)
var _ vault.Importer = (*Importer)(nil)
