package cryptoutils

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/hex"
	"fmt"
	"math/big"
	"sync"

	"github.com/decred/dcrd/dcrec/secp256k1"
)

/*
const (
	// CurveED25519
	CurveED25519 = "ed25519"

	// CurveP256 is the standard name for P256 Curve
	CurveP256 = "P-256"
	// SigP256 is the standard name for ES256 Signature algorithm
	SigP256 = "ES256"

	// CurveP256K is the standard name for P256K Curve
	CurveP256K = "P-256K"
	// CurveP256KAlternate is the an alternate name for P256K Curve
	CurveP256KAlternate = "SECP256K1"
	// SigP256K is the standard name for ES256K Signature algorithm
	SigP256K = "ES256K"
	// SigP256KAlternate is the an alternate name for ES256K Signature algorithm
	SigP256KAlternate = "ECDSA256"
)
*/

// CanonizeECDSASignature returns the canonical versions of the signature
// the canonical version enforce low S values
// if S is above order / 2 it negating the S (modulo the order (N))
func CanonizeECDSASignature(curve elliptic.Curve, sig *ECDSASignature) *ECDSASignature {
	r := new(big.Int).Set(sig.R)
	s := new(big.Int).Set(sig.S)

	order := curve.Params().N
	quo := new(big.Int).Quo(order, new(big.Int).SetInt64(2))
	if s.Cmp(quo) > 0 {
		s = s.Sub(order, s)
	}

	return &ECDSASignature{
		R: r,
		S: s,
	}
}

// CanonizeSignature returns the canonical versions of the ECDSA signature if one is given
func CanonizeSignature(pub crypto.PublicKey, sig Signature) Signature {
	epub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return sig
	}
	s, ok := sig.(*ECDSASignature)
	if !ok {
		return sig
	}

	return CanonizeECDSASignature(epub.Curve, s)
}

// Signature is a type representing a digital signature.
type Signature interface {
	String() string
}

// ECDSASignature is a type representing an ecdsa signature.
type ECDSASignature struct {
	R *big.Int
	S *big.Int
}

func (e *ECDSASignature) String() string {
	return fmt.Sprintf("ecdsa:[r:%s,s:%s]", hex.EncodeToString(e.R.Bytes()), hex.EncodeToString(e.S.Bytes()))
}

// ED25519Signature is a type representing an Ed25519 signature
type ED25519Signature []byte

func (e ED25519Signature) String() string {
	return fmt.Sprintf("ed25519:[%s]", hex.EncodeToString(e))
}

var (
	initS256  sync.Once
	s256Curve secp256k1.KoblitzCurve
)

// S256 S256 returns a Curve which implements secp256k1 with correct name
func S256() *secp256k1.KoblitzCurve {
	initS256.Do(func() {
		s256Curve = *secp256k1.S256()
		if s256Curve.CurveParams.Name != "" {
			return
		}
		// github.com/decred/dcrd/dcrec/secp256k1 leaves the name empty, fix it
		cp := *s256Curve.CurveParams
		cp.Name = "P-256K"
		s256Curve.CurveParams = &cp
	})

	return &s256Curve
}

// CurveEqual returns true if curves are equal regardless of names and pointer values
func CurveEqual(a, b elliptic.Curve) bool {
	ap, bp := a.Params(), b.Params()
	return ap.P.Cmp(bp.P) == 0 &&
		ap.N.Cmp(bp.N) == 0 &&
		ap.B.Cmp(bp.B) == 0 &&
		ap.Gx.Cmp(bp.Gx) == 0 &&
		ap.Gy.Cmp(bp.Gy) == 0 &&
		ap.BitSize == bp.BitSize
}

// PrivateKey is omplemented by private key types
type PrivateKey interface {
	Public() crypto.PublicKey
}
