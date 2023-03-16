package cryptoutils

import (
	"crypto/elliptic"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

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
		return secp256k1.S256()
	default:
		return nil
	}
}
