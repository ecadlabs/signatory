package crypt

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"fmt"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/ecadlabs/goblst/minpk"
	tz "github.com/ecadlabs/gotez"
	"github.com/ecadlabs/gotez/b58"
	"golang.org/x/crypto/blake2b"
)

var Digest = blake2b.Sum256

type PublicKeyHash = tz.PublicKeyHash

type PrivateKey interface {
	tz.Base58Encoder
	ToProtocol() tz.PrivateKey
	Sign(message []byte) (signature Signature, err error)
	Public() PublicKey
	Equal(PrivateKey) bool
	Unwrap() crypto.PrivateKey
}

type PublicKey interface {
	tz.Base58Encoder
	ToProtocol() tz.PublicKey
	VerifySignature(sig Signature, message []byte) bool
	Hash() PublicKeyHash
	Equal(PublicKey) bool
	Unwrap() crypto.PublicKey
}

type Signature interface {
	tz.Base58Encoder
	ToProtocol() tz.Signature
	Verify(pub PublicKey, message []byte) bool
}

func NewPrivateKey(priv tz.PrivateKey) (PrivateKey, error) {
	switch key := priv.(type) {
	case *tz.Ed25519PrivateKey:
		if len(key) != ed25519.SeedSize {
			panic("crypt: invalid Ed25519 private key length") // unlikely
		}
		return Ed25519PrivateKey(ed25519.NewKeyFromSeed(key[:])), nil

	case *tz.Secp256k1PrivateKey:
		p, err := unmarshalPrivateKey(key[:], secp256k1.S256())
		if err != nil {
			return nil, err
		}
		return (*ECDSAPrivateKey)(p), nil

	case *tz.P256PrivateKey:
		p, err := unmarshalPrivateKey(key[:], elliptic.P256())
		if err != nil {
			return nil, err
		}
		return (*ECDSAPrivateKey)(p), nil

	case *tz.BLSPrivateKey:
		p, err := minpk.PrivateKeyFromBytes(key[:])
		if err != nil {
			return nil, err
		}
		return (*BLSPrivateKey)(p), nil

	default:
		return nil, fmt.Errorf("crypt: unknown private key type: %T", priv)
	}
}

func NewPublicKey(pub tz.PublicKey) (PublicKey, error) {
	switch pub := pub.(type) {
	case *tz.Ed25519PublicKey:
		if len(pub) != ed25519.PublicKeySize {
			panic("crypt: invalid ed25519 public key length") // unlikely
		}
		return Ed25519PublicKey(pub[:]), nil

	case *tz.Secp256k1PublicKey, *tz.P256PublicKey:
		var (
			curve elliptic.Curve
			data  []byte
		)
		switch key := pub.(type) {
		case *tz.Secp256k1PublicKey:
			curve = secp256k1.S256()
			data = key[:]
		case *tz.P256PublicKey:
			curve = elliptic.P256()
			data = key[:]
		default:
			panic("unreachable")
		}
		x, y, err := unmarshalCompressed(data, curve)
		if err != nil {
			return nil, err
		}
		return (*ECDSAPublicKey)(&ecdsa.PublicKey{
			Curve: curve,
			X:     x,
			Y:     y,
		}), nil

	case *tz.BLSPublicKey:
		p, err := minpk.PublicKeyFromBytes(pub[:])

		if err != nil {
			return nil, err
		}
		return (*BLSPublicKey)(p), nil

	default:
		return nil, fmt.Errorf("crypt: unknown public key type: %T", pub)
	}
}

func NewSignature(sig tz.Signature) (Signature, error) {
	switch sig := sig.(type) {
	case *tz.GenericSignature:
		return (*GenericSignature)(sig), nil

	case *tz.Ed25519Signature:
		if len(sig) != ed25519.SignatureSize {
			panic("crypt: invalid ed25519 signature length") // unlikely
		}
		return Ed25519Signature(sig[:]), nil

	case *tz.Secp256k1Signature:
		r, s := sig.Point()
		return &ECDSASignature{
			R:     r,
			S:     s,
			Curve: secp256k1.S256(),
		}, nil

	case *tz.P256Signature:
		r, s := sig.Point()
		return &ECDSASignature{
			R:     r,
			S:     s,
			Curve: elliptic.P256(),
		}, nil

	case *tz.BLSSignature:
		s, err := minpk.SignatureFromBytes(sig[:])
		if err != nil {
			return nil, err
		}
		return (*BLSSignature)(s), nil

	default:
		return nil, fmt.Errorf("crypt: unknown signature type: %T", sig)
	}
}

func ParsePrivateKey(src []byte) (PrivateKey, error) {
	priv, err := b58.ParsePrivateKey(src)
	if err != nil {
		return nil, err
	}
	return NewPrivateKey(priv)
}

func ParsePublicKey(src []byte) (PublicKey, error) {
	priv, err := b58.ParsePublicKey(src)
	if err != nil {
		return nil, err
	}
	return NewPublicKey(priv)
}

func ParseSignature(src []byte) (Signature, error) {
	sig, err := b58.ParseSignature(src)
	if err != nil {
		return nil, err
	}
	return NewSignature(sig)
}

type GenericSignature tz.GenericSignature

func (sig *GenericSignature) ToBase58() []byte {
	return (*tz.GenericSignature)(sig).ToBase58()
}

func (sig *GenericSignature) String() string {
	return string(sig.ToBase58())
}

func (sig *GenericSignature) Verify(pub PublicKey, message []byte) bool {
	return pub.VerifySignature(sig, message)
}

func (sig *GenericSignature) ToProtocol() tz.Signature {
	return (*tz.GenericSignature)(sig)
}
