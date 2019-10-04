package vault

import (
	"context"
	"crypto"
	"fmt"

	"github.com/ecadlabs/signatory/pkg/cryptoutils"
	"gopkg.in/yaml.v3"
)

// StoredKey represents a public key which has a private counterpart stored on the backend side
type StoredKey interface {
	PublicKey() crypto.PublicKey
	ID() string
}

// Vault interface that represent a secure key store
type Vault interface {
	GetPublicKey(ctx context.Context, id string) (StoredKey, error)
	ListPublicKeys(ctx context.Context) ([]StoredKey, error)
	Sign(ctx context.Context, digest []byte, key StoredKey) (cryptoutils.Signature, error)
	Name() string
}

// Importer interface representing an importer backend
type Importer interface {
	Vault
	Import(ctx context.Context, pk cryptoutils.PrivateKey) (StoredKey, error)
}

// VaultNamer might be implemented by some backends which can handle multiple vaults under single account
type VaultNamer interface {
	VaultName() string
}

// ReadinessChecker is an optional interface implemented by a backend
type ReadinessChecker interface {
	Ready(ctx context.Context) (bool, error)
}

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
