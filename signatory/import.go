package signatory

import (
	"encoding/base64"

	"github.com/ecadlabs/signatory/tezos"
)

// JWK struct containing a standard key format
type JWK struct {
	KeyType string `json:"kty"`
	D       string `json:"d"`
	X       string `json:"x"`
	Y       string `json:"y"`
	Curve   string `json:"crv"`
}

// ImportedKey struct containing information about an imported key
type ImportedKey struct {
	Hash  string
	KeyID string
}

// KeyPair interface that represent an elliptic curve key pair
type KeyPair interface {
	X() []byte
	Y() []byte
	D() []byte
	CurveName() string
}

// Import a keyPair inside the vault
func Import(pubkey string, secretKey string, vault Vault) (*ImportedKey, error) {
	keyPair := tezos.NewKeyPair(pubkey, secretKey)
	err := keyPair.Validate()

	if err != nil {
		return nil, err
	}

	jwk, err := ToJWK(keyPair)

	if err != nil {
		return nil, err
	}

	keyID, err := vault.Import(jwk)

	if err != nil {
		return nil, err
	}

	hash, err := keyPair.PubKeyHash()

	if err != nil {
		return nil, err
	}

	importedKey := &ImportedKey{
		KeyID: keyID,
		Hash:  hash,
	}

	return importedKey, nil
}

// ToJWK Convert a keyPair to a JWK
func ToJWK(k KeyPair) (*JWK, error) {
	return &JWK{
		X:       base64.StdEncoding.EncodeToString(k.X()),
		Y:       base64.StdEncoding.EncodeToString(k.Y()),
		D:       base64.StdEncoding.EncodeToString(k.D()),
		KeyType: "EC",
		Curve:   k.CurveName(),
	}, nil
}
