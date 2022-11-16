package auth

import (
	"context"
	"crypto"
	stderr "errors"
	"net/http"

	"github.com/ecadlabs/signatory/pkg/errors"
)

// ErrPublicKeyNotFound is returned by AuthorizedKeysStorage.GetPublicKey if authorized key is not found
var ErrPublicKeyNotFound = errors.Wrap(stderr.New("public key not found"), http.StatusUnauthorized)

// AuthorizedKeysStorage represents an authorized public keys storage
type AuthorizedKeysStorage interface {
	GetPublicKey(ctx context.Context, keyHash string) (crypto.PublicKey, error)
	ListPublicKeys(ctx context.Context) ([]string, error)
}

// Must panics in case of error
func Must(s AuthorizedKeysStorage, err error) AuthorizedKeysStorage {
	if err != nil {
		panic(err)
	}
	return s
}
