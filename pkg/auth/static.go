package auth

import (
	"context"
	"crypto"

	tz "github.com/ecadlabs/gotez"
	"github.com/ecadlabs/gotez/hashmap"
)

type authorizedKeys = hashmap.HashMap[tz.EncodedPublicKeyHash, tz.PublicKeyHash, crypto.PublicKey]
type staticAuthorizedKeys struct {
	idx  authorizedKeys
	keys []tz.PublicKeyHash
}

func (s *staticAuthorizedKeys) GetPublicKey(ctx context.Context, keyHash tz.PublicKeyHash) (crypto.PublicKey, error) {
	pk, ok := s.idx.Get(keyHash)
	if !ok {
		return nil, ErrPublicKeyNotFound
	}
	return pk, nil
}

func (s *staticAuthorizedKeys) ListPublicKeys(ctx context.Context) ([]tz.PublicKeyHash, error) {
	return s.keys, nil
}

// StaticAuthorizedKeys returns an AuthorizedKeysStorage that uses the given public keys
func StaticAuthorizedKeys(pub ...crypto.PublicKey) (AuthorizedKeysStorage, error) {
	idx := make(authorizedKeys)
	keys := make([]tz.PublicKeyHash, len(pub))
	for i, k := range pub {
		pk, err := tz.NewPublicKey(k)
		if err != nil {
			return nil, err
		}
		pkh := pk.Hash()
		keys[i] = pkh
		idx.Insert(pkh, k)
	}
	return &staticAuthorizedKeys{
		idx:  idx,
		keys: keys,
	}, nil
}

// StaticAuthorizedKeysFromRaw returns an AuthorizedKeysStorage that uses the given public keys
func StaticAuthorizedKeysFromRaw(pub ...tz.PublicKey) (AuthorizedKeysStorage, error) {
	idx := make(authorizedKeys)
	keys := make([]tz.PublicKeyHash, len(pub))
	for i, k := range pub {
		pk, err := k.PublicKey()
		if err != nil {
			return nil, err
		}
		pkh := k.Hash()
		keys[i] = pkh
		idx.Insert(pkh, pk)
	}
	return &staticAuthorizedKeys{
		idx:  idx,
		keys: keys,
	}, nil
}
