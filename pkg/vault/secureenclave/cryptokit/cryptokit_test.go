//go:build darwin

package cryptokit

import (
	"testing"

	"github.com/ecadlabs/gotez/v2/crypt"
	"github.com/ecadlabs/signatory/pkg/cryptoutils"
	"github.com/stretchr/testify/require"
)

func TestNewKey(t *testing.T) {
	priv, err := NewPrivateKey()
	require.NoError(t, err)

	p, err := cryptoutils.ParsePKIXPublicKey(priv.Public().DERBytes())
	require.NoError(t, err)
	pub, err := crypt.NewPublicKeyFrom(p)
	require.NoError(t, err)

	src := []byte("text text text")
	digest := crypt.DigestFunc(src)

	s, err := priv.Sign((*[32]byte)(&digest))
	require.NoError(t, err)
	sig, err := crypt.NewSignatureFromBytes(s.DERBytes(), pub)
	require.NoError(t, err)

	require.True(t, pub.VerifySignature(sig, src))
}
