// Package memory provides a basis for file based and in-memory vaults
package memory

import (
	"context"
	"fmt"
	"sync"

	"github.com/ecadlabs/gotez/v2/b58"
	"github.com/ecadlabs/gotez/v2/crypt"
	"github.com/ecadlabs/signatory/pkg/utils"
	"github.com/ecadlabs/signatory/pkg/vault"
)

type PrivateKey struct {
	Key crypt.PrivateKey
	ID  string
}

type UnparsedKey struct {
	Data string
	ID   string
}

type keyRef struct {
	*PrivateKey
	v *Vault
}

type popKeyRef struct {
	keyRef
}

func (k *keyRef) PublicKey() crypt.PublicKey { return k.Key.Public() }
func (k *keyRef) Vault() vault.Vault         { return k.v }
func (k *keyRef) Sign(ctx context.Context, message []byte, opt *vault.SignOptions) (sig crypt.Signature, err error) {
	var signature crypt.Signature
	if blsKey, ok := k.Key.(*crypt.BLSPrivateKey); ok {
		ver := utils.BlsVersionLatest
		if opt != nil {
			ver = opt.Version
		}
		switch ver {
		case utils.BlsVersion0:
			err = fmt.Errorf("(%s): BlsVersion0 is not supported", k.v.name)
		case utils.BlsVersion1:
			signature, err = blsKey.SignAugmented(message)
		case utils.BlsVersion2:
			signature, err = blsKey.Sign(message)
		default:
			signature, err = blsKey.Sign(message)
		}
	} else {
		signature, err = k.Key.Sign(message)
	}
	if err != nil {
		return nil, fmt.Errorf("(%s): %w", k.v.name, err)
	}
	return signature, nil
}

func (k *popKeyRef) ProvePossession(ctx context.Context) (crypt.Signature, error) {
	key := k.Key.(*crypt.BLSPrivateKey)
	return key.ProvePossession(), nil
}

// Vault is a file system based vault
type Vault struct {
	raw      []*UnparsedKey
	keys     []*PrivateKey
	mtx      sync.Mutex
	name     string
	unlocked bool
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
func New(keys []*PrivateKey, name string) (*Vault, error) {
	if name == "" {
		name = "Mem"
	}
	return &Vault{
		name:     name,
		keys:     keys,
		unlocked: true,
	}, nil
}

func (v *Vault) newKeyRef(key *PrivateKey) vault.KeyReference {
	k := keyRef{
		PrivateKey: key,
		v:          v,
	}
	if _, ok := key.Key.(*crypt.BLSPrivateKey); ok {
		return &popKeyRef{
			keyRef: k,
		}
	}
	return &k
}

// List list all public key available on disk
func (v *Vault) List(ctx context.Context) vault.KeyIterator {
	v.mtx.Lock()
	defer v.mtx.Unlock()

	snap := v.keys
	i := 0
	return vault.IteratorFunc(func() (key vault.KeyReference, err error) {
		if i >= len(snap) {
			return nil, vault.ErrDone
		}
		k := v.newKeyRef(snap[i])
		i++
		return k, nil
	})
}

// Name returns backend name
func (v *Vault) Name() string { return v.name }

// Unlock unlock all encrypted keys on disk
func (v *Vault) Unlock(ctx context.Context) error {
	v.mtx.Lock()
	if v.unlocked {
		v.mtx.Unlock()
		return nil
	}
	v.mtx.Unlock()

	keys := make([]*PrivateKey, len(v.raw))

	for i, entry := range v.raw {
		name := entry.ID
		if name == "" {
			name = "<unnamed>"
		}

		tzPrivEnc, err := b58.ParseEncryptedPrivateKey([]byte(entry.Data))
		if err != nil {
			return fmt.Errorf("(%s): %w", v.name, err)
		}
		tzPriv, err := tzPrivEnc.Decrypt(utils.KeyboardInteractivePassphraseFunc(fmt.Sprintf("(%s): Enter password to unlock key `%s': ", v.name, name)))
		if err != nil {
			return fmt.Errorf("(%s): %w", v.name, err)
		}
		priv, err := crypt.NewPrivateKey(tzPriv)
		if err != nil {
			return fmt.Errorf("(%s): %w", v.name, err)
		}

		key := PrivateKey{
			Key: priv,
			ID:  entry.ID,
		}
		keys[i] = &key
	}

	v.mtx.Lock()
	defer v.mtx.Unlock()

	v.keys = keys
	v.unlocked = true

	return nil
}

func (v *Vault) ImportKey(ctx context.Context, priv crypt.PrivateKey, opt utils.Options) (vault.KeyReference, error) {
	id, _, err := opt.GetString("name")
	if err != nil {
		return nil, fmt.Errorf("(%s): %w", v.name, err)
	}

	key := &PrivateKey{
		Key: priv,
		ID:  id,
	}

	v.mtx.Lock()
	defer v.mtx.Unlock()
	v.keys = append(v.keys, key)

	return v.newKeyRef(key), nil
}

func (v *Vault) Close(context.Context) error { return nil }

type Importer struct {
	*Vault
}

func (i *Importer) Import(ctx context.Context, pk crypt.PrivateKey, opt utils.Options) (vault.KeyReference, error) {
	return i.ImportKey(ctx, pk, opt)
}

var _ vault.Unlocker = (*Vault)(nil)
var _ vault.Importer = (*Importer)(nil)
