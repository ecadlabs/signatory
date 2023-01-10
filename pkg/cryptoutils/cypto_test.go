package cryptoutils

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCrypto(t *testing.T) {
	r := new(big.Int)
	s := new(big.Int)
	r.SetString("20681563462996749847132572347697104495131755095539024135364977879663893820746", 10)
	s.SetString("71021938819329713221438400365751029842736242550542230996637874923543387825226", 10)
	sig := &ECDSASignature{
		R: new(big.Int).Set(r),
		S: new(big.Int).Set(s),
	}

	require.NotPanics(t, func() { _ = CanonizeSignature(sig) })
}
