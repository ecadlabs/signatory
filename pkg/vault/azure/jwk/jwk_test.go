package jwk

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	stdx509 "crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"testing"

	"github.com/ecadlabs/signatory/pkg/cryptoutils/x509"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func bigInt(s string, base int) *big.Int {
	v, _ := new(big.Int).SetString(s, base)
	return v
}

func parsePrivateKey(buf []byte) (pk interface{}, err error) {
	block, _ := pem.Decode(buf)
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing the private key")
	}

	if block.Type == "RSA PRIVATE KEY" {
		return stdx509.ParsePKCS1PrivateKey(block.Bytes)
	}

	return x509.ParsePKCS8PrivateKey(block.Bytes) // Unencrypted PKCS#8 only
}

func parsePublicKey(buf []byte) (pk interface{}, err error) {
	block, _ := pem.Decode(buf)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, errors.New("failed to parse PEM block containing the public key")
	}

	return x509.ParsePKIXPublicKey(block.Bytes)
}

func TestParse(t *testing.T) {
	type testCase struct {
		jsonData      string
		expectPub     interface{}
		expectPubPem  string
		expectPubErr  error
		expectPriv    interface{}
		expectPrivPem string
		expectPrivErr error
	}

	cases := []testCase{
		{
			jsonData: `{"kty":"EC","crv":"P-256","x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4","y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM","d":"870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE"}`,
			expectPriv: &ecdsa.PrivateKey{
				PublicKey: ecdsa.PublicKey{
					Curve: elliptic.P256(),
					X:     bigInt("21994169848703329112137818087919262246467304847122821377551355163096090930238", 10),
					Y:     bigInt("101451294974385619524093058399734017814808930032421185206609461750712400090915", 10),
				},
				D: bigInt("110246039328358150430804407946042381407500908316371398015658902487828646033409", 10),
			},
			expectPub: &ecdsa.PublicKey{
				Curve: elliptic.P256(),
				X:     bigInt("21994169848703329112137818087919262246467304847122821377551355163096090930238", 10),
				Y:     bigInt("101451294974385619524093058399734017814808930032421185206609461750712400090915", 10),
			},
		},
		{
			jsonData:      `{"kty":"EC","crv":"P-256K","x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4","y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM","d":"870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE"}`,
			expectPrivErr: errors.New("jwk: invalid point: 21994169848703329112137818087919262246467304847122821377551355163096090930238, 101451294974385619524093058399734017814808930032421185206609461750712400090915"),
			expectPubErr:  errors.New("jwk: invalid point: 21994169848703329112137818087919262246467304847122821377551355163096090930238, 101451294974385619524093058399734017814808930032421185206609461750712400090915"),
		},
		{
			jsonData:      `{"kty":"EC","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"}`,
			expectPrivErr: ErrPublic,
			expectPub: &ecdsa.PublicKey{
				Curve: elliptic.P256(),
				X:     bigInt("57807358241436249728379122087876380298924820027722995515715270765240753673285", 10),
				Y:     bigInt("90436541859143682268950424386863654389577770182238183823381687388274600502701", 10),
			},
		},
	}

	as := assert.New(t)
	for _, tst := range cases {
		var j JWK
		require.NoError(t, json.Unmarshal([]byte(tst.jsonData), &j))

		priv, err := j.PrivateKey()
		as.Equal(tst.expectPrivErr, err)

		var expect interface{}
		if tst.expectPrivPem != "" {
			expect, err = parsePrivateKey([]byte(tst.expectPrivPem))
			require.NoError(t, err)
		} else {
			expect = tst.expectPriv
		}
		as.Equal(expect, priv)

		if expect != nil {
			jj, err := EncodePrivateKey(expect.(crypto.PrivateKey))
			require.NoError(t, err)
			as.Equal(&j, jj)
		}

		pub, err := j.PublicKey()
		as.Equal(tst.expectPubErr, err)

		if tst.expectPubPem != "" {
			expect, err = parsePublicKey([]byte(tst.expectPubPem))
			require.NoError(t, err)
		} else {
			expect = tst.expectPub
		}
		as.Equal(expect, pub)
	}
}
