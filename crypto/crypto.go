package crypto

import (
	"crypto/elliptic"

	"github.com/decred/dcrd/dcrec/secp256k1"
)

const (
	// CurveP256 is the standard name for P256 Curve
	CurveP256 = "P-256"
	// SigP256 is the standard name for ES256 Signature algorithm
	SigP256 = "ES256"

	// CurveP256K is the standard name for P256K Curve
	CurveP256K = "P-256K"
	// SigP256K is the standard name for ES256K Signature algorithm
	SigP256K = "ES256K"
)

func getCurve(name string) elliptic.Curve {
	if name == CurveP256 {
		return elliptic.P256()
	}
	if name == CurveP256K {
		return secp256k1.S256()
	}
	return nil
}

// ECCoordinateFromPrivateKey given an elliptic curve name it will produce X and Y coordiante from D
func ECCoordinateFromPrivateKey(d []byte, curveName string) (xBytes, yBytes []byte) {
	curve := getCurve(curveName)
	x, y := curve.ScalarBaseMult(d)
	xBytes = x.Bytes()
	yBytes = y.Bytes()
	return
}
