package cryptoutils

import (
	"crypto/elliptic"
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCryptoCanonizeSignature(t *testing.T) {
	r := new(big.Int)
	s := new(big.Int)
	sc := new(big.Int)
	r.SetString("20681563462996749847132572347697104495131755095539024135364977879663893820746", 10)
	s.SetString("71021938819329713221438400365751029842736242550542230996637874923543387825226", 10)
	sc.SetString("44770150391026535541259046583656543687260712673593529345784384137525124219143", 10)
	sig := &ECDSASignature{
		R: new(big.Int).Set(r),
		S: new(big.Int).Set(s),
	}
	var nocurve, curved *ECDSASignature

	t.Run("Without curve", func(t *testing.T) {
		require.NotPanics(t, func() { nocurve = CanonizeSignature(sig).(*ECDSASignature) })
		require.Nil(t, nocurve.Curve)
		sig.Curve = elliptic.P256()
	})

	t.Run("With curve", func(t *testing.T) {
		require.NotPanics(t, func() { curved = CanonizeSignature(sig).(*ECDSASignature) })
		require.Equal(t, sc, curved.S)
		require.NotNil(t, curved.Curve)
	})
}
