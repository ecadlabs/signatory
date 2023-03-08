//go:build !integration

package cryptoutils

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPKCS(t *testing.T) {
	pk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	standard, err := x509.MarshalPKCS8PrivateKey(pk)
	require.NoError(t, err)

	our, err := MarshalPKCS8PrivateKey(pk)
	require.NoError(t, err)

	require.Equal(t, standard, our)
}

func TestParsePublikKey(t *testing.T) {
	pk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	standard, err := x509.MarshalPKIXPublicKey(&pk.PublicKey)
	require.NoError(t, err)

	ppk, err := ParsePKIXPublicKey(standard)
	require.NoError(t, err)

	require.Equal(t, pk, ppk)
}
