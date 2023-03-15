package auth

import (
	"context"
	"crypto"
	stderr "errors"
	"net/http"

	"github.com/ecadlabs/gotez"
	"github.com/ecadlabs/signatory/pkg/errors"
)

// ErrPublicKeyNotFound is returned by AuthorizedKeysStorage.GetPublicKey if authorized key is not found
var ErrPublicKeyNotFound = errors.Wrap(stderr.New("public key not found"), http.StatusUnauthorized)

// AuthorizedKeysStorage represents an authorized public keys storage
type AuthorizedKeysStorage interface {
	GetPublicKey(ctx context.Context, keyHash gotez.PublicKeyHash) (crypto.PublicKey, error)
	ListPublicKeys(ctx context.Context) ([]gotez.PublicKeyHash, error)
}

// Must panics in case of error
func Must(s AuthorizedKeysStorage, err error) AuthorizedKeysStorage {
	if err != nil {
		panic(err)
	}
	return s
}
