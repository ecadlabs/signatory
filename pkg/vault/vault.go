package vault

import (
	"context"
	"crypto"
	"errors"
	"fmt"

	"github.com/ecadlabs/signatory/pkg/cryptoutils"
	"github.com/ecadlabs/signatory/pkg/utils"
	"github.com/spf13/cobra"
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

// RawSigner may be implemented by some vaults that expect raw data instead of a precomputed hash
type RawSigner interface {
	SignRaw(ctx context.Context, data []byte, key StoredKey) (cryptoutils.Signature, error)
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
	Import(ctx context.Context, pk cryptoutils.PrivateKey, opt utils.Options) (StoredKey, error)
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

var vaultRegistry = make(map[string]newVaultFunc)

func RegisterVault(name string, newFunc newVaultFunc) {
	vaultRegistry[name] = newFunc
}

var commands []*cobra.Command

func RegisterCommand(cmd *cobra.Command) {
	commands = append(commands, cmd)
}

func Commands() []*cobra.Command {
	return commands
}

// NewVault returns new vault instance
func NewVault(ctx context.Context, name string, conf *yaml.Node) (Vault, error) {
	if newFunc, ok := vaultRegistry[name]; ok {
		return newFunc(ctx, conf)
	}

	return nil, fmt.Errorf("unknown vault driver: %s", name)
}
