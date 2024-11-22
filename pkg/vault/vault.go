package vault

import (
	"context"
	"errors"
	"fmt"

	"github.com/ecadlabs/gotez/v2/crypt"
	"github.com/ecadlabs/signatory/pkg/utils"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

// KeyReference represents a public key which has a private counterpart stored on the backend side
type KeyReference interface {
	PublicKey() crypt.PublicKey
	Sign(ctx context.Context, message []byte) (crypt.Signature, error)
	Vault() Vault
}

type WithID interface {
	KeyReference
	ID() string // Additional backend specific ID that can be displayed alongside the public key
}

// KeyIterator is used to iterate over stored public keys
type KeyIterator interface {
	Next() (KeyReference, error)
}

type IteratorFunc func() (key KeyReference, err error)

func (i IteratorFunc) Next() (key KeyReference, err error) { return i() }

// Vault interface that represent a secure key store
type Vault interface {
	List(ctx context.Context) KeyIterator
	Close(ctx context.Context) error
	Name() string
}

// Importer interface representing an importer backend
type Importer interface {
	Vault
	Import(ctx context.Context, pk crypt.PrivateKey, opt utils.Options) (KeyReference, error)
}

// Unlocker interface representing an unlocker backend
type Unlocker interface {
	Vault
	Unlock(ctx context.Context) error
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

type newVaultFunc func(ctx context.Context, conf *yaml.Node) (Vault, error)

type Factory interface {
	New(ctx context.Context, name string, conf *yaml.Node) (Vault, error)
}

type FactoryFunc func(ctx context.Context, name string, conf *yaml.Node) (Vault, error)

func (f FactoryFunc) New(ctx context.Context, name string, conf *yaml.Node) (Vault, error) {
	return f(ctx, name, conf)
}

type registry map[string]newVaultFunc

func (r registry) New(ctx context.Context, name string, conf *yaml.Node) (Vault, error) {
	if newFunc, ok := r[name]; ok {
		return newFunc(ctx, conf)
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

var commands []*cobra.Command

func RegisterCommand(cmd *cobra.Command) {
	commands = append(commands, cmd)
}

func Commands() []*cobra.Command {
	return commands
}

func Collect(it KeyIterator) ([]KeyReference, error) {
	var keys []KeyReference
keyLoop:
	for {
		key, err := it.Next()
		if err != nil {
			switch {
			case errors.Is(err, ErrDone):
				break keyLoop
			case errors.Is(err, ErrKey):
				continue keyLoop
			default:
				return nil, err
			}
		}
		keys = append(keys, key)
	}
	return keys, nil
}

var _ Factory = (registry)(nil)
