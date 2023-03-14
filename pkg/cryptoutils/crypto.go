package cryptoutils

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	blst "github.com/ecadlabs/goblst"
	"github.com/ecadlabs/goblst/minpk"
	"github.com/ecadlabs/gotez/signature"
	"golang.org/x/crypto/blake2b"
)

// Digest is an alias for blake2b checksum algorithm
var Digest = blake2b.Sum256

func canonizeECDSASignature(sig *signature.ECDSA) *signature.ECDSA {
	r := new(big.Int).Set(sig.R)
	s := new(big.Int).Set(sig.S)

	if sig.Curve != nil {
		order := sig.Curve.Params().N
		quo := new(big.Int).Quo(order, new(big.Int).SetInt64(2))
		if s.Cmp(quo) > 0 {
			s = s.Sub(order, s)
		}
	}

	return &signature.ECDSA{
		R:     r,
		S:     s,
		Curve: sig.Curve,
	}
}

// Signature is a type representing a digital signature.
type Signature = signature.Signature

// S256 returns a Curve which implements secp256k1
func S256() elliptic.Curve {
	return secp256k1.S256()
}

// PrivateKey is implemented by private key types
type PrivateKey = crypto.Signer

// NamedCurve returns curve by its standard name or nil
func NamedCurve(name string) elliptic.Curve {
	switch name {
	case "P-224":
		return elliptic.P224()
	case "P-256":
		return elliptic.P256()
	case "P-384":
		return elliptic.P384()
	case "P-521":
		return elliptic.P521()
	case "P-256K", "SECP256K1", "secp256k1":
		return S256()
	default:
		return nil
	}
}

// Sign sign a hash using this private key
func Sign(priv PrivateKey, msg []byte) (Signature, error) {
	switch key := priv.(type) {
	case *ecdsa.PrivateKey:
		digest := Digest(msg)
		r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
		if err != nil {
			return nil, err
		}
		return canonizeECDSASignature(&signature.ECDSA{R: r, S: s, Curve: key.Curve}), nil
	case ed25519.PrivateKey:
		digest := Digest(msg)
		return signature.ED25519(ed25519.Sign(key, digest[:])), nil
	case *minpk.PrivateKey:
		return minpk.Sign(key, msg, blst.Augmentation), nil
	}
	return nil, fmt.Errorf("unsupported key type: %T", priv)
}

var (
	// ErrSignature error returned by Verify if signature is invalid
	ErrSignature = errors.New("invalid signature")
)

// Verify verifies the signature
func Verify(pub crypto.PublicKey, msg []byte, sig Signature) error {
	switch key := pub.(type) {
	case *ecdsa.PublicKey:
		digest := Digest(msg)
		s, ok := sig.(*signature.ECDSA)
		if !ok {
			return ErrSignature
		}
		if ok = ecdsa.Verify(key, digest[:], s.R, s.S); !ok {
			return ErrSignature
		}
	case ed25519.PublicKey:
		digest := Digest(msg)
		s, ok := sig.(signature.ED25519)
		if !ok {
			return ErrSignature
		}
		if ok = ed25519.Verify(key, digest[:], s); !ok {
			return ErrSignature
		}
	case *minpk.PublicKey:
		s, ok := sig.(*minpk.Signature)
		if !ok {
			return ErrSignature
		}
		if err := minpk.Verify(key, msg, s, blst.Augmentation); err != nil {
			return ErrSignature
		}

	default:
		return fmt.Errorf("unsupported key type: %T", pub)
	}

	return nil
}

// PublicKeySuitable returns true if the key is Tezos compatible
func PublicKeySuitableForTezos(pub crypto.PublicKey) bool {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		switch k.Curve {
		case elliptic.P256(), S256():
			return true
		default:
			return false
		}

	case ed25519.PublicKey, *minpk.PublicKey:
		return true

	default:
		return false
	}
}
