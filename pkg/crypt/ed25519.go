package crypt

import (
	"crypto"
	"crypto/ed25519"

	tz "github.com/ecadlabs/gotez"
)

type Ed25519PrivateKey ed25519.PrivateKey

func (priv Ed25519PrivateKey) ToBase58() []byte {
	return priv.ToProtocol().ToBase58()
}

func (priv Ed25519PrivateKey) String() string {
	return priv.ToProtocol().String()
}

func (priv Ed25519PrivateKey) Public() PublicKey {
	return Ed25519PublicKey(ed25519.PrivateKey(priv).Public().(ed25519.PublicKey))
}

func (priv Ed25519PrivateKey) Sign(message []byte) (signature Signature, err error) {
	digest := Digest(message)
	return Ed25519Signature(ed25519.Sign(ed25519.PrivateKey(priv), digest[:])), nil
}

func (priv Ed25519PrivateKey) ToProtocol() tz.PrivateKey {
	return tz.NewEd25519PrivateKey(ed25519.PrivateKey(priv).Seed())
}

func (priv Ed25519PrivateKey) Equal(other PrivateKey) bool {
	x, ok := other.(Ed25519PrivateKey)
	return ok && ed25519.PrivateKey(priv).Equal(ed25519.PrivateKey(x))
}

func (priv Ed25519PrivateKey) MarshalText() (text []byte, err error) {
	return priv.Public().ToBase58(), nil
}

func (priv Ed25519PrivateKey) Unwrap() crypto.PrivateKey {
	return ed25519.PrivateKey(priv)
}

func (priv Ed25519PrivateKey) Seed() []byte {
	return ed25519.PrivateKey(priv).Seed()
}

type Ed25519PublicKey ed25519.PublicKey

func (pub Ed25519PublicKey) Hash() PublicKeyHash {
	return pub.ToProtocol().Hash()
}

func (pub Ed25519PublicKey) ToBase58() []byte {
	return pub.ToProtocol().ToBase58()
}

func (pub Ed25519PublicKey) String() string {
	return pub.ToProtocol().String()
}

func (pub Ed25519PublicKey) ToProtocol() tz.PublicKey {
	return tz.NewEd25519PublicKey(pub)
}

func (pub Ed25519PublicKey) Equal(other PublicKey) bool {
	x, ok := other.(Ed25519PublicKey)
	return ok && ed25519.PublicKey(pub).Equal(ed25519.PublicKey(x))
}

func (pub Ed25519PublicKey) MarshalText() (text []byte, err error) {
	return pub.ToProtocol().ToBase58(), nil
}

func (pub Ed25519PublicKey) VerifySignature(sig Signature, message []byte) bool {
	digest := Digest(message)
	switch sig := sig.(type) {
	case Ed25519Signature:
		return ed25519.Verify(ed25519.PublicKey(pub), digest[:], sig)
	case *GenericSignature:
		return ed25519.Verify(ed25519.PublicKey(pub), digest[:], sig[:])
	default:
		return false
	}
}

func (pub Ed25519PublicKey) Unwrap() crypto.PublicKey {
	return ed25519.PublicKey(pub)
}

type Ed25519Signature []byte

func NewEd25519Signature(sig *tz.Ed25519Signature) Ed25519Signature {
	return Ed25519Signature(sig[:])
}

func (sig Ed25519Signature) ToBase58() []byte {
	return sig.ToProtocol().ToBase58()
}

func (sig Ed25519Signature) String() string {
	return sig.ToProtocol().String()
}

func (sig Ed25519Signature) Verify(pub PublicKey, message []byte) bool {
	return pub.VerifySignature(sig, message)
}

func (sig Ed25519Signature) ToProtocol() tz.Signature {
	return tz.NewEd25519Signature(sig)
}

func (sig Ed25519Signature) MarshalText() (text []byte, err error) {
	return sig.ToProtocol().ToBase58(), nil
}

var _ PrivateKey = Ed25519PrivateKey{}
