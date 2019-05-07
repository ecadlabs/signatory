package signatory_test

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/ecadlabs/signatory/config"
	"github.com/ecadlabs/signatory/signatory"
	"github.com/ecadlabs/signatory/tezos"
)

type VaultMock struct{}

func (v *VaultMock) Contains(keyHash string) bool                { return true }
func (v *VaultMock) GetPublicKey(keyHash string) ([]byte, error) { return []byte{}, nil }
func (v *VaultMock) ListPublicKeys() ([][]byte, error)           { return [][]byte{}, nil }
func (v *VaultMock) Import(jwk *signatory.JWK) (string, error)   { return "", nil }
func (v *VaultMock) Name() string                                { return "Mock" }
func (v *VaultMock) Sign(message []byte, key string, alg string) ([]byte, error) {
	return []byte{}, nil
}

func TestToJWK(t *testing.T) {
	s := signatory.NewSignatory([]signatory.Vault{&VaultMock{}}, &config.TezosConfig{})
	keyPair := tezos.NewKeyPair("p2pk67PsiUBJZq9twKoFAWt8fSSVn53BR31dxKnTeLirLxHqB8gSnCq", "p2sk3LiJ6fU9Lvh8tdwar6tJ2Xg9bg3kQ9p4Sjmn83m29qJQdQPA5r")
	jwk, err := s.ToJWK(keyPair)

	if err != nil {
		fmt.Printf("Unexpected error was thrown: %s\n", err.Error())
		t.Fail()
	}

	expected := &signatory.JWK{
		X:       "c7q7ikPWrTV2PtkXZU7nBLf64IxkBC+7neE1hMhubO4=",
		Y:       "qw4Gy13NjXk7fuD+0V74TnzY5IZEMEFr7urURuUQHMc=",
		D:       "g4T+8SoekVVckF4rnuBapHgqZEFpewA1KkrSxzwgoSA=",
		KeyType: "EC",
		Curve:   "P-256",
	}

	if !reflect.DeepEqual(jwk, expected) {
		fmt.Printf("TestToJWK \n expected: \n%+v\n received: \n%+v\n", expected, jwk)
		t.Fail()
	}
}
