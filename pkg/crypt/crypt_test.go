package crypt

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/ecadlabs/goblst/minpk"
	tz "github.com/ecadlabs/gotez"
	"github.com/ecadlabs/gotez/b58"
	"github.com/stretchr/testify/require"
)

type testCase struct {
	title  string
	genKey func() PrivateKey
}

var cases = []testCase{
	{
		title: "Ed25519",
		genKey: func() PrivateKey {
			_, k, _ := ed25519.GenerateKey(rand.Reader)
			return Ed25519PrivateKey(k)
		},
	},
	{
		title: "Secp256k1",
		genKey: func() PrivateKey {
			k, _ := ecdsa.GenerateKey(secp256k1.S256(), rand.Reader)
			return (*ECDSAPrivateKey)(k)
		},
	},
	{
		title: "P256",
		genKey: func() PrivateKey {
			k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			return (*ECDSAPrivateKey)(k)
		},
	},
	{
		title: "BLS",
		genKey: func() PrivateKey {
			k, _ := minpk.GenerateKey(rand.Reader)
			return (*BLSPrivateKey)(k)
		},
	},
}

func TestKey(t *testing.T) {
	for _, c := range cases {
		t.Run(c.title, func(t *testing.T) {
			// generate key
			priv := c.genKey()
			// encode to internal roundtrip
			tzPriv := priv.ToProtocol()
			tmp, err := NewPrivateKey(tzPriv)
			require.NoError(t, err)
			require.True(t, priv.Equal(tmp))
			require.Equal(t, priv, tmp)

			// encode to base58 roundtrip
			tmp2, err := ParsePrivateKey(priv.ToBase58())
			require.NoError(t, err)
			require.True(t, priv.Equal(tmp2))

			// encode to base58 roundtrip using encrypted type
			tmp3, err := b58.ParsePrivateKey(tzPriv.ToBase58())
			require.NoError(t, err)
			decrypted, err := tmp3.Decrypt(nil)
			require.NoError(t, err)
			require.Equal(t, tzPriv, decrypted)

			// get public
			pub := priv.Public()
			// encode to internal roundtrip
			tzPub := pub.ToProtocol()
			tmp4, err := NewPublicKey(tzPub)
			require.NoError(t, err)
			require.True(t, pub.Equal(tmp4))
			require.Equal(t, pub, tmp4)

			// encode to base58 roundtrip
			tmp5, err := ParsePublicKey(pub.ToBase58())
			require.NoError(t, err)
			require.True(t, pub.Equal(tmp5))
		})
	}
}

func asGeneric(sig tz.Signature) tz.Signature {
	switch sig := sig.(type) {
	case *tz.Ed25519Signature:
		return (*tz.GenericSignature)(sig)
	case *tz.Secp256k1Signature:
		return (*tz.GenericSignature)(sig)
	case *tz.P256Signature:
		return (*tz.GenericSignature)(sig)
	case *tz.BLSSignature:
		return nil
	default:
		panic("unknown")
	}
}

func TestSignature(t *testing.T) {
	var message = []byte("message text")

	for _, c := range cases {
		t.Run(c.title, func(t *testing.T) {
			priv := c.genKey()
			sig, err := priv.Sign(message)
			require.NoError(t, err)

			sig1, err := NewSignature(sig.ToProtocol())
			require.NoError(t, err)
			require.Equal(t, sig, sig1)

			sig2, err := ParseSignature(sig.ToBase58())
			require.NoError(t, err)
			require.Equal(t, sig, sig2)

			require.True(t, sig.Verify(priv.Public(), message))

			// via generic
			if genSig := asGeneric(sig.ToProtocol()); genSig != nil {
				sig, err := NewSignature(genSig)
				require.NoError(t, err)
				require.True(t, sig.Verify(priv.Public(), message))
			}
		})
	}
}
