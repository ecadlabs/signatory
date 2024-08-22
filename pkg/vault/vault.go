package vault

import (
	"context"
	"errors"
	"fmt"

	"github.com/ecadlabs/gotez/v2/crypt"
	"github.com/ecadlabs/signatory/pkg/config"
	"github.com/ecadlabs/signatory/pkg/utils"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

// StoredKey represents a public key which has a private counterpart stored on the backend side
type StoredKey interface {
	PublicKey() crypt.PublicKey
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
	SignMessage(ctx context.Context, msg []byte, key StoredKey) (crypt.Signature, error)
	Name() string
}

// Importer interface representing an importer backend
type Importer interface {
	Vault
	Import(ctx context.Context, pk crypt.PrivateKey, opt utils.Options) (StoredKey, error)
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
var (
	ErrDone = errors.New("done")
	ErrKey  = errors.New("unsupported key type")
)

type newVaultFunc func(ctx context.Context, conf *yaml.Node, g config.GlobalContext) (Vault, error)

type Factory interface {
	New(ctx context.Context, name string, conf *yaml.Node, g config.GlobalContext) (Vault, error)
}

type FactoryFunc func(ctx context.Context, name string, conf *yaml.Node, g config.GlobalContext) (Vault, error)

func (f FactoryFunc) New(ctx context.Context, name string, conf *yaml.Node, g config.GlobalContext) (Vault, error) {
	return f(ctx, name, conf, g)
}

type registry map[string]newVaultFunc

func (r registry) New(ctx context.Context, name string, conf *yaml.Node, g config.GlobalContext) (Vault, error) {
	if newFunc, ok := r[name]; ok {
		return newFunc(ctx, conf, g)
	}
	return nil, fmt.Errorf("unknown vault driver: %s", name)
}

var vaultRegistry = make(registry)

func RegisterVault(name string, newFunc newVaultFunc) {
	vaultRegistry[name] = newFunc
}

func Registry() Factory {
	return vaultRegistry
}

type CommandFunc func(c config.GlobalContext) *cobra.Command

var commands []CommandFunc

func RegisterCommand(fn CommandFunc) {
	commands = append(commands, fn)
}

func Commands(ctx config.GlobalContext) []*cobra.Command {
	cmd := make([]*cobra.Command, len(commands))
	for i, c := range commands {
		cmd[i] = c(ctx)
	}
	return cmd
}

var _ Factory = (registry)(nil)
