package auth

import (
	"context"

	tz "github.com/ecadlabs/gotez"
	"github.com/ecadlabs/signatory/pkg/crypt"
	"github.com/ecadlabs/signatory/pkg/hashmap"
)

type authorizedKeys = hashmap.HashMap[tz.EncodedPublicKeyHash, crypt.PublicKeyHash, crypt.PublicKey]
type staticAuthorizedKeys struct {
	idx  authorizedKeys
	keys []crypt.PublicKeyHash
}

func (s *staticAuthorizedKeys) GetPublicKey(ctx context.Context, keyHash crypt.PublicKeyHash) (crypt.PublicKey, error) {
	pk, ok := s.idx.Get(keyHash)
	if !ok {
		return nil, ErrPublicKeyNotFound
	}
	return pk, nil
}

func (s *staticAuthorizedKeys) ListPublicKeys(ctx context.Context) ([]crypt.PublicKeyHash, error) {
	return s.keys, nil
}

// StaticAuthorizedKeys returns an AuthorizedKeysStorage that uses the given public keys
func StaticAuthorizedKeys(pub ...crypt.PublicKey) (AuthorizedKeysStorage, error) {
	idx := make(authorizedKeys)
	keys := make([]crypt.PublicKeyHash, len(pub))
	for i, pk := range pub {
		pkh := pk.Hash()
		keys[i] = pkh
		idx.Insert(pkh, pk)
	}
	return &staticAuthorizedKeys{
		idx:  idx,
		keys: keys,
	}, nil
}

// StaticAuthorizedKeysFromRaw returns an AuthorizedKeysStorage that uses the given public keys
func StaticAuthorizedKeysFromRaw(pub ...tz.PublicKey) (AuthorizedKeysStorage, error) {
	idx := make(authorizedKeys)
	keys := make([]crypt.PublicKeyHash, len(pub))
	for i, k := range pub {
		pk, err := crypt.NewPublicKey(k)
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
