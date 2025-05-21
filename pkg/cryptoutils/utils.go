package cryptoutils

import (
	"github.com/ecadlabs/gotez/v2/b58/base58"
	"github.com/ecadlabs/gotez/v2/b58/prefix"
)

type KeyType prefix.Prefix

var (
	KeyEd25519   = (*KeyType)(&prefix.Ed25519Seed)
	KeySecp256k1 = (*KeyType)(&prefix.Secp256k1SecretKey)
	KeyP256      = (*KeyType)(&prefix.P256SecretKey)
	KeyBLS12_381 = (*KeyType)(&prefix.BLS12_381SecretKey)
)

func (k *KeyType) String() string { return string(base58.Encode(k.Prefix)) }

func KeyTypeFromString(src string) *KeyType {
	switch src {
	case "ed25519", "tz1":
		return KeyEd25519
	case "secp256k1", "tz2":
		return KeySecp256k1
	case "p256", "tz3":
		return KeyP256
	case "bls", "tz4":
		return KeyBLS12_381
	default:
		return nil
	}
}
