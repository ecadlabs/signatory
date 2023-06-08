package crypt

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"math/big"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	tz "github.com/ecadlabs/gotez"
)

type ECDSAPrivateKey ecdsa.PrivateKey

func (priv *ECDSAPrivateKey) ToBase58() []byte {
	return priv.ToProtocol().ToBase58()
}

func (priv *ECDSAPrivateKey) String() string {
	return priv.ToProtocol().String()
}

func (priv *ECDSAPrivateKey) Public() PublicKey {
	return (*ECDSAPublicKey)((*ecdsa.PrivateKey)(priv).Public().(*ecdsa.PublicKey))
}

func (priv *ECDSAPrivateKey) Sign(message []byte) (signature Signature, err error) {
	digest := DigestFunc(message)
	r, s, err := ecdsa.Sign(rand.Reader, (*ecdsa.PrivateKey)(priv), digest[:])
	if err != nil {
		return nil, err
	}
	sig := &ECDSASignature{
		R:     r,
		S:     s,
		Curve: (*ecdsa.PrivateKey)(priv).Curve,
	}
	return canonizeSignature(sig), nil
}

func (priv *ECDSAPrivateKey) ToProtocol() tz.PrivateKey {
	switch priv.Curve {
	case elliptic.P256():
		return tz.NewP256PrivateKey(priv.D)
	case secp256k1.S256():
		return tz.NewSecp256k1PrivateKey(priv.D)
	default:
		panic(fmt.Sprintf("crypt: unknown curve: %v", priv.Curve.Params()))
	}
}

func (priv *ECDSAPrivateKey) Equal(other PrivateKey) bool {
	x, ok := other.(*ECDSAPrivateKey)
	return ok && (*ecdsa.PrivateKey)(priv).Equal((*ecdsa.PrivateKey)(x))
}

func (priv *ECDSAPrivateKey) MarshalText() (text []byte, err error) {
	return priv.ToProtocol().ToBase58(), nil
}

func (priv *ECDSAPrivateKey) Unwrap() crypto.PrivateKey {
	return (*ecdsa.PrivateKey)(priv)
}

type ECDSAPublicKey ecdsa.PublicKey

func (pub *ECDSAPublicKey) Hash() PublicKeyHash {
	return pub.ToProtocol().Hash()
}

func (pub *ECDSAPublicKey) ToBase58() []byte {
	return pub.ToProtocol().ToBase58()
}

func (pub *ECDSAPublicKey) String() string {
	return pub.ToProtocol().String()
}

func (pub *ECDSAPublicKey) VerifySignature(sig Signature, message []byte) bool {
	digest := DigestFunc(message)
	switch sig := sig.(type) {
	case *ECDSASignature:
		return ecdsa.Verify((*ecdsa.PublicKey)(pub), digest[:], sig.R, sig.S)
	case *GenericSignature:
		s, err := NewSignature((*tz.Secp256k1Signature)(sig)) // exact curve doesn't matter here
		if err != nil {
			return false
		}
		return s.Verify(pub, message)
	default:
		return false
	}
}

func (pub *ECDSAPublicKey) ToProtocol() tz.PublicKey {
	switch pub.Curve {
	case elliptic.P256():
		return tz.NewP256PublicKey(elliptic.MarshalCompressed(pub.Curve, pub.X, pub.Y))
	case secp256k1.S256():
		return tz.NewSecp256k1PublicKey(elliptic.MarshalCompressed(pub.Curve, pub.X, pub.Y))
	default:
		panic(fmt.Sprintf("crypt: unknown curve: %v", pub.Curve.Params()))
	}
}

func (pub *ECDSAPublicKey) Equal(other PublicKey) bool {
	x, ok := other.(*ECDSAPublicKey)
	return ok && (*ecdsa.PublicKey)(pub).Equal((*ecdsa.PublicKey)(x))
}

func (pub *ECDSAPublicKey) MarshalText() (text []byte, err error) {
	return pub.ToProtocol().ToBase58(), nil
}

func (pub *ECDSAPublicKey) Unwrap() crypto.PublicKey {
	return (*ecdsa.PublicKey)(pub)
}

type ECDSASignature struct {
	R     *big.Int
	S     *big.Int
	Curve elliptic.Curve
}

func (sig *ECDSASignature) ToBase58() []byte {
	return sig.ToProtocol().ToBase58()
}

func (sig *ECDSASignature) String() string {
	return sig.ToProtocol().String()
}

func (sig *ECDSASignature) Verify(pub PublicKey, message []byte) bool {
	return pub.VerifySignature(sig, message)
}

func (sig *ECDSASignature) ToProtocol() tz.Signature {
	var s tz.Signature
	switch sig.Curve {
	case secp256k1.S256():
		s = tz.NewSecp256k1Signature(sig.R, sig.S)
	case elliptic.P256():
		s = tz.NewP256Signature(sig.R, sig.S)
	default:
		panic(fmt.Sprintf("crypt: unknown curve %v", sig.Curve.Params()))
	}
	return s
}

func (sig *ECDSASignature) MarshalText() (text []byte, err error) {
	return sig.ToProtocol().ToBase58(), nil
}

func canonizeSignature(sig *ECDSASignature) *ECDSASignature {
	r := new(big.Int).Set(sig.R)
	s := new(big.Int).Set(sig.S)

	order := sig.Curve.Params().N
	quo := new(big.Int).Quo(order, new(big.Int).SetInt64(2))
	if s.Cmp(quo) > 0 {
		s = s.Sub(order, s)
	}

	return &ECDSASignature{
		R:     r,
		S:     s,
		Curve: sig.Curve,
	}
}

// See https://github.com/golang/go/blob/master/src/crypto/elliptic/elliptic.go
func unmarshalCompressed(data []byte, curve elliptic.Curve) (x, y *big.Int, err error) {
	byteLen := (curve.Params().BitSize + 7) / 8
	if len(data) != 1+byteLen {
		return nil, nil, ErrInvalidPublicKey
	}
	if data[0] != 2 && data[0] != 3 { // compressed form
		return nil, nil, ErrInvalidPublicKey
	}
	p := curve.Params().P
	x = new(big.Int).SetBytes(data[1:])
	if x.Cmp(p) >= 0 {
		return nil, nil, ErrInvalidPublicKey
	}

	// secp256k1 polynomial: x³ + b
	// P-* polynomial: x³ - 3x + b
	y = new(big.Int).Mul(x, x)
	y.Mul(y, x)
	if curve != secp256k1.S256() {
		x1 := new(big.Int).Lsh(x, 1)
		x1.Add(x1, x)
		y.Sub(y, x1)
	}
	y.Add(y, curve.Params().B)
	y.Mod(y, curve.Params().P)
	y.ModSqrt(y, p)

	if y == nil {
		return nil, nil, ErrInvalidPublicKey
	}
	if byte(y.Bit(0)) != data[0]&1 {
		y.Neg(y).Mod(y, p)
	}
	if !curve.IsOnCurve(x, y) {
		return nil, nil, ErrInvalidPublicKey
	}
	return
}

// see https://golang.org/src/crypto/x509/sec1.go
func unmarshalPrivateKey(b []byte, curve elliptic.Curve) (key *ecdsa.PrivateKey, err error) {
	k := new(big.Int).SetBytes(b)
	curveOrder := curve.Params().N
	if k.Cmp(curveOrder) >= 0 {
		return nil, ErrInvalidPrivateKey
	}

	priv := ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: curve,
		},
		D: k,
	}

	privateKey := make([]byte, (curveOrder.BitLen()+7)/8)
	// Some private keys have leading zero padding. This is invalid
	// according to [SEC1], but this code will ignore it.
	for len(b) > len(privateKey) {
		if b[0] != 0 {
			return nil, ErrInvalidPrivateKey
		}
		b = b[1:]
	}

	// Some private keys remove all leading zeros, this is also invalid
	// according to [SEC1] but since OpenSSL used to do this, we ignore
	// this too.
	copy(privateKey[len(privateKey)-len(b):], b)
	priv.X, priv.Y = curve.ScalarBaseMult(privateKey)

	return &priv, nil
}

var _ PrivateKey = &ECDSAPrivateKey{}
