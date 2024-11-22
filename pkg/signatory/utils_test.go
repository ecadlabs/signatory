//go:build !integration

package signatory_test

import (
	"context"

	"github.com/ecadlabs/signatory/pkg/vault"
)

type GetPublicKey func(ctx context.Context, id string) (vault.KeyReference, error)
type ListPublicKeys func(ctx context.Context) vault.KeyIterator
type Name func() string
type Next func() (vault.KeyReference, error)

type TestVault struct {
	gp GetPublicKey
	lp ListPublicKeys
	na Name
}

func NewTestVault(g GetPublicKey, l ListPublicKeys, n Name, vn string) *TestVault {
	return &TestVault{
		gp: g,
		lp: l,
		na: n,
	}
}

type testKeyIterator struct {
	idx int
	nth func(idx int) (key vault.KeyReference, err error)
}

func NewTestIterator(nth func(idx int) (key vault.KeyReference, err error)) *testKeyIterator {
	return &testKeyIterator{
		nth: nth,
	}
}

func (it *testKeyIterator) Next() (key vault.KeyReference, err error) {
	key, err = it.nth(it.idx)
	it.idx += 1
	return
}

func (v *TestVault) List(ctx context.Context) vault.KeyIterator {
	return v.lp(ctx)
}

func (v *TestVault) Name() string                { return v.na() }
func (v *TestVault) Close(context.Context) error { return nil }
