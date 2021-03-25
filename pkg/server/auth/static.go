package auth

import (
	"context"
	"crypto"

	"github.com/ecadlabs/signatory/pkg/tezos"
)

type staticAuthorizedKeys struct {
	idx  map[string]crypto.PublicKey
	keys []string
}

func (s *staticAuthorizedKeys) GetPublicKey(ctx context.Context, keyHash string) (crypto.PublicKey, error) {
	pk, ok := s.idx[keyHash]
	if !ok {
		return nil, ErrPublicKeyNotFound
	}
	return pk, nil
}

func (s *staticAuthorizedKeys) ListPublicKeys(ctx context.Context) ([]string, error) {
	return s.keys, nil
}

// StaticAuthorizedKeys returns an AuthorizedKeysStorage that uses the given public keys
func StaticAuthorizedKeys(pub ...crypto.PublicKey) (AuthorizedKeysStorage, error) {
	idx := make(map[string]crypto.PublicKey)
	keys := make([]string, len(pub))
	for i, k := range pub {
		pkh, err := tezos.EncodePublicKeyHash(k)
		if err != nil {
			return nil, err
		}
		keys[i] = pkh
		idx[pkh] = k
	}
	return &staticAuthorizedKeys{
		idx:  idx,
		keys: keys,
	}, nil
}

// StaticAuthorizedKeysFromString returns an AuthorizedKeysStorage that uses the given public keys
func StaticAuthorizedKeysFromString(pub ...string) (AuthorizedKeysStorage, error) {
	keys := make([]crypto.PublicKey, len(pub))
	for i, s := range pub {
		k, err := tezos.ParsePublicKey(s)
		if err != nil {
			return nil, err
		}
		keys[i] = k
	}
	return StaticAuthorizedKeys(keys...)
}
