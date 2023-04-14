package cryptoutils

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"testing"

	"github.com/ecadlabs/signatory/pkg/crypt"
	"github.com/stretchr/testify/require"
)

func TestPKCS(t *testing.T) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	pk := (*crypt.ECDSAPrivateKey)(k)

	standard, err := x509.MarshalPKCS8PrivateKey(pk.Unwrap())
	require.NoError(t, err)

	our1, err := MarshalPKCS8PrivateKey(pk)
	require.NoError(t, err)
	require.Equal(t, standard, our1)

	our2, err := MarshalPKCS8PrivateKey(pk.Unwrap())
	require.NoError(t, err)
	require.Equal(t, standard, our2)
}
