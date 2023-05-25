package crypt

import (
	"crypto"

	bls "github.com/ecadlabs/goblst"
	"github.com/ecadlabs/goblst/minpk"
	tz "github.com/ecadlabs/gotez"
)

type BLSPrivateKey minpk.PrivateKey

func (priv *BLSPrivateKey) ToBase58() []byte {
	return priv.ToProtocol().ToBase58()
}

func (priv *BLSPrivateKey) String() string {
	return priv.ToProtocol().String()
}

func (priv *BLSPrivateKey) Public() PublicKey {
	return (*BLSPublicKey)((*minpk.PrivateKey)(priv).Public().(*minpk.PublicKey))
}

func (priv *BLSPrivateKey) Sign(message []byte) (signature Signature, err error) {
	sig := minpk.Sign((*minpk.PrivateKey)(priv), message, bls.Augmentation)
	return (*BLSSignature)(sig), nil
}

func (priv *BLSPrivateKey) ToProtocol() tz.PrivateKey {
	return tz.NewBLSPrivateKey((*minpk.PrivateKey)(priv).Bytes())
}

func (priv *BLSPrivateKey) Equal(other PrivateKey) bool {
	x, ok := other.(*BLSPrivateKey)
	return ok && (*minpk.PrivateKey)(priv).Equal((*minpk.PrivateKey)(x))
}

func (priv *BLSPrivateKey) MarshalText() (text []byte, err error) {
	return priv.ToProtocol().ToBase58(), nil
}

func (priv *BLSPrivateKey) Unwrap() crypto.PrivateKey {
	return (*minpk.PrivateKey)(priv)
}

type BLSPublicKey minpk.PublicKey

func (pub *BLSPublicKey) Hash() PublicKeyHash {
	return pub.ToProtocol().Hash()
}

func (pub *BLSPublicKey) ToBase58() []byte {
	return pub.ToProtocol().ToBase58()
}

func (pub *BLSPublicKey) String() string {
	return pub.ToProtocol().String()
}

func (pub *BLSPublicKey) ToProtocol() tz.PublicKey {
	return tz.NewBLSPublicKey((*minpk.PublicKey)(pub).Bytes())
}

func (pub *BLSPublicKey) Equal(other PublicKey) bool {
	x, ok := other.(*BLSPublicKey)
	return ok && (*minpk.PublicKey)(pub).Equal((*minpk.PublicKey)(x))
}

func (pub *BLSPublicKey) VerifySignature(sig Signature, message []byte) bool {
	switch sig := sig.(type) {
	case *BLSSignature:
		return minpk.Verify((*minpk.PublicKey)(pub), message, (*minpk.Signature)(sig), bls.Augmentation) == nil
	default:
		return false
	}
}

func (pub *BLSPublicKey) MarshalText() (text []byte, err error) {
	return pub.ToProtocol().ToBase58(), nil
}

func (pub *BLSPublicKey) Unwrap() crypto.PublicKey {
	return (*minpk.PublicKey)(pub)
}

type BLSSignature minpk.Signature

func (sig *BLSSignature) ToBase58() []byte {
	return sig.ToProtocol().ToBase58()
}

func (sig *BLSSignature) String() string {
	return sig.ToProtocol().String()
}

func (sig *BLSSignature) Verify(pub PublicKey, message []byte) bool {
	return pub.VerifySignature(sig, message)
}

func (sig *BLSSignature) ToProtocol() tz.Signature {
	return tz.NewBLSSignature((*minpk.Signature)(sig).Bytes())
}

func (sig *BLSSignature) MarshalText() (text []byte, err error) {
	return sig.ToProtocol().ToBase58(), nil
}

var _ PrivateKey = &BLSPrivateKey{}
