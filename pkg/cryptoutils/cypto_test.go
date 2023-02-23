package cryptoutils_test

import (
	"crypto/elliptic"
	"math/big"
	"testing"

	"github.com/ecadlabs/signatory/pkg/cryptoutils"
	"github.com/ecadlabs/signatory/pkg/tezos"
	"github.com/stretchr/testify/require"
)

func TestCryptoCanonizeSignature(t *testing.T) {
	r := new(big.Int)
	s := new(big.Int)
	sc := new(big.Int)
	r.SetString("20681563462996749847132572347697104495131755095539024135364977879663893820746", 10)
	s.SetString("71021938819329713221438400365751029842736242550542230996637874923543387825226", 10)
	sc.SetString("44770150391026535541259046583656543687260712673593529345784384137525124219143", 10)
	sig := &cryptoutils.ECDSASignature{
		R: new(big.Int).Set(r),
		S: new(big.Int).Set(s),
	}
	var nocurve, curved *cryptoutils.ECDSASignature

	t.Run("Without curve", func(t *testing.T) {
		require.NotPanics(t, func() { nocurve = cryptoutils.CanonizeSignature(sig).(*cryptoutils.ECDSASignature) })
		require.Nil(t, nocurve.Curve)
		sig.Curve = elliptic.P256()
	})

	t.Run("With curve", func(t *testing.T) {
		require.NotPanics(t, func() { curved = cryptoutils.CanonizeSignature(sig).(*cryptoutils.ECDSASignature) })
		require.Equal(t, sc, curved.S)
		require.NotNil(t, curved.Curve)
	})
}

func TestSignVerify(t *testing.T) {
	pk := "edsk4FTF78Qf1m2rykGpHqostAiq5gYW4YZEoGUSWBTJr2njsDHSnd"
	priv, err := tezos.ParsePrivateKey(pk, nil)
	require.NoError(t, err)
	signature, err := cryptoutils.Sign(priv, []byte("Hello"))
	require.NoError(t, err)
	err = cryptoutils.Verify(priv.Public(), []byte("Hello"), signature)
	require.NoError(t, err)
}
