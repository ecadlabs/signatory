//go:build darwin

package cryptokit

import (
	"bytes"
	"testing"

	"github.com/ecadlabs/gotez/v2/crypt"
	"github.com/ecadlabs/signatory/pkg/cryptoutils"
	"github.com/stretchr/testify/require"
)

func TestCryptoKit(t *testing.T) {
	if !IsAvailable() {
		return
	}

	t.Run("Sign", func(t *testing.T) {
		priv, err := NewPrivateKey()
		require.NoError(t, err)

		p, err := cryptoutils.ParsePKIXPublicKey(priv.Public().DERBytes())
		require.NoError(t, err)
		pub, err := crypt.NewPublicKeyFrom(p)
		require.NoError(t, err)

		src := []byte("text text text")
		digest := crypt.DigestFunc(src)

		s, err := priv.Signature((*[32]byte)(&digest))
		require.NoError(t, err)
		sig, err := crypt.NewSignatureFromBytes(s.DERBytes(), pub)
		require.NoError(t, err)

		require.True(t, pub.VerifySignature(sig, src))
	})

	t.Run("NewKeyFromData", func(t *testing.T) {
		priv1, err := NewPrivateKey()
		require.NoError(t, err)

		priv2, err := NewPrivateKeyFromData(priv1.Bytes())
		require.NoError(t, err)

		require.True(t, bytes.Equal(priv1.Public().DERBytes(), priv2.Public().DERBytes()))
	})

	t.Run("NewKeyFromDataError", func(t *testing.T) {
		_, err := NewPrivateKeyFromData(make([]byte, 100))
		require.Error(t, err, "cryptotokenkit: the data was corrupted")
	})
}
