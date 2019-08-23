package crypto

import (
	"crypto/elliptic"
	"math/big"

	"github.com/decred/dcrd/dcrec/secp256k1"
)

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

func GetCurve(name string) elliptic.Curve {
	if name == CurveP256 {
		return elliptic.P256()
	}
	if name == CurveP256K {
		return secp256k1.S256()
	}
	return nil
}

// ECCoordinateFromPrivateKey given an elliptic curve name it will produce X and Y coordinate from D
func ECCoordinateFromPrivateKey(d []byte, curveName string) (xBytes, yBytes []byte) {
	curve := GetCurve(curveName)

	if curve == nil {
		return nil, nil
	}

	x, y := curve.ScalarBaseMult(d)
	xBytes = x.Bytes()
	yBytes = y.Bytes()
	return
}

// CanonizeEncodeP256K returns the canonical versions of the signature
// the canonical version enforce low S values
// if S is above order / 2 it negating the S (modulo the order (N))
func CanonizeEncodeP256K(sig []byte) []byte {
	r := sig[:32]
	s := sig[32:]
	rInt := new(big.Int).SetBytes(r)
	sInt := new(big.Int).SetBytes(s)

	order := secp256k1.S256().N
	two := new(big.Int).SetBytes([]byte{0x02})
	quo := new(big.Int).Quo(order, two)
	if sInt.Cmp(quo) > 0 {
		sInt = sInt.Sub(order, sInt)
	}

	s = sInt.Bytes()
	r = rInt.Bytes()
	signature := append(r, s...)
	return signature
}
