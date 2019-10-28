package vault

import (
	"context"
	"crypto"
	"errors"
	"fmt"

	"github.com/ecadlabs/signatory/pkg/cryptoutils"
	"gopkg.in/yaml.v3"
)

// StoredKey represents a public key which has a private counterpart stored on the backend side
type StoredKey interface {
	PublicKey() crypto.PublicKey
	ID() string
}

// StoredKeysIterator is used to iterate over stored public keys
type StoredKeysIterator interface {
	Next() (StoredKey, error)
}

// Vault interface that represent a secure key store
type Vault interface {
	GetPublicKey(ctx context.Context, id string) (StoredKey, error)
	ListPublicKeys(ctx context.Context) StoredKeysIterator
	Sign(ctx context.Context, digest []byte, key StoredKey) (cryptoutils.Signature, error)
	Name() string
}

// Importer interface representing an importer backend
type Importer interface {
	Vault
	Import(ctx context.Context, pk cryptoutils.PrivateKey) (StoredKey, error)
}

// Unlocker interface representing an unlocker backend
type Unlocker interface {
	Vault
	Unlock(ctx context.Context) error
}

// VaultNamer might be implemented by some backends which can handle multiple vaults under single account
type VaultNamer interface {
	VaultName() string
}

// ReadinessChecker is an optional interface implemented by a backend
type ReadinessChecker interface {
	Ready(ctx context.Context) (bool, error)
}

// ErrDone is the error returned by iterator when the iteration is done.
var ErrDone = errors.New("done")

type newVaultFunc func(ctx context.Context, conf *yaml.Node) (Vault, error)

var registry = make(map[string]newVaultFunc)

func RegisterVault(name string, newFunc newVaultFunc) {
	registry[name] = newFunc
}

// NewVault returns new vault instance
func NewVault(ctx context.Context, name string, conf *yaml.Node) (Vault, error) {
	if newFunc, ok := registry[name]; ok {
		return newFunc(ctx, conf)
	}

	return nil, fmt.Errorf("Unknown vault driver: %s", name)
}
