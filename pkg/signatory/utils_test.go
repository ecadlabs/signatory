package signatory_test

import (
	"context"

	"github.com/ecadlabs/signatory/pkg/cryptoutils"
	"github.com/ecadlabs/signatory/pkg/vault"
)

type GetPublicKey func(ctx context.Context, id string) (vault.StoredKey, error)
type ListPublicKeys func(ctx context.Context) vault.StoredKeysIterator
type Sign func(ctx context.Context, digest []byte, key vault.StoredKey) (cryptoutils.Signature, error)
type Name func() string
type Next func() (vault.StoredKey, error)

type TestVault struct {
	name string
	gp   GetPublicKey
	lp   ListPublicKeys
	s    Sign
	n    Name
}

func NewTestVault(g GetPublicKey, l ListPublicKeys, s Sign, na Name, n string) *TestVault {

	return &TestVault{
		name: n,
		lp:   l,
	}
}

type TestKeyIterator struct {
	nxt Next
}

func (it *TestKeyIterator) Next() (key vault.StoredKey, err error) {
	return it.nxt()
}
func (v *TestVault) GetPublicKey(ctx context.Context, id string) (vault.StoredKey, error) {
	return v.gp(ctx, id)
}
func (v *TestVault) ListPublicKeys(ctx context.Context) vault.StoredKeysIterator {
	return v.lp(ctx)
}
func (v *TestVault) Sign(ctx context.Context, digest []byte, key vault.StoredKey) (cryptoutils.Signature, error) {
	return v.s(ctx, digest, key)
}
func (v *TestVault) Name() string { return v.n() }
