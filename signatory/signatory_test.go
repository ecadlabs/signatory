package signatory_test

import (
	"fmt"
	"testing"

	"github.com/ecadlabs/signatory/config"
	"github.com/ecadlabs/signatory/signatory"
	"github.com/ecadlabs/signatory/watermark"
)

type FakeVault struct {
	ContainsFunc func(keyHash string) bool
}

func (v *FakeVault) Contains(keyHash string) bool                             { return v.ContainsFunc(keyHash) }
func (v *FakeVault) GetPublicKey(keyHash string) (signatory.StoredKey, error) { return nil, nil }
func (v *FakeVault) ListPublicKeys() ([]signatory.StoredKey, error) {
	return []signatory.StoredKey{}, nil
}
func (v *FakeVault) Import(jwk *signatory.JWK) (string, error) { return "", nil }
func (v *FakeVault) Name() string                              { return "Mock" }
func (v *FakeVault) Sign(message []byte, storedKey signatory.StoredKey) ([]byte, error) {
	return []byte{}, nil
}

func TestGetPublicKeyNoVault(t *testing.T) {
	s := signatory.NewSignatory(
		[]signatory.Vault{&FakeVault{
			ContainsFunc: func(keyHash string) bool { return false },
		}},
		&config.TezosConfig{},
		func(address string, vault string, kind string) {},
		watermark.NewIgnore(),
	)

	_, err := s.GetPublicKey("Unkown address")

	if err != signatory.ErrVaultNotFound {
		fmt.Printf("Unexpected error was thrown: %s\n", err.Error())
		t.Fail()
	}
}
