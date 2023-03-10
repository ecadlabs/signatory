package tezos

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/ecadlabs/signatory/pkg/cryptoutils"
	"github.com/stretchr/testify/assert"
)

type TestBadSignature struct {
	val []byte
}

func (ts *TestBadSignature) String() string {
	return string(ts.val)
}

func NewTestSignature(val []byte) *TestBadSignature {
	ts := TestBadSignature{val: val}
	return &ts
}

func Test_EncodeGenericSignature_FailureUnknownType(t *testing.T) {
	bad := []byte("bad")
	sig := NewTestSignature(bad)
	encoded, err := EncodeGenericSignature(sig)
	assert.Equal(t, "", encoded)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unknown signature type")
	assert.Contains(t, err.Error(), "("+string(bad)+")")
}

func Test_EncodeGenericSignature_Success(t *testing.T) {
	message := []byte("somedata")
	pub, pk, err := ed25519.GenerateKey(rand.Reader)
	assert.Nil(t, err)
	sig, err := cryptoutils.Sign(pk, message)
	assert.Nil(t, err)
	encoded, err := EncodeGenericSignature(sig)
	assert.Nil(t, err)
	assert.NotNil(t, encoded)
	parsed, err := ParseSignature(encoded, pub)
	assert.Nil(t, err)
	assert.NotNil(t, parsed)
	assert.Equal(t, sig, parsed)
}

func Test_EncodeSignature_SuccessEd25519(t *testing.T) {
	message := []byte("somedata")
	pub, pk, err := ed25519.GenerateKey(rand.Reader)
	assert.Nil(t, err)
	sig, err := cryptoutils.Sign(pk, message)
	assert.Nil(t, err)
	encoded, err := EncodeSignature(sig)
	assert.Nil(t, err)
	assert.NotNil(t, encoded)
	parsed, err := ParseSignature(encoded, pub)
	assert.Nil(t, err)
	assert.NotNil(t, parsed)
	assert.Equal(t, sig, parsed)
}

func Test_EncodeSignature_SuccessEcdsaP256(t *testing.T) {
	message := []byte("somedata")
	pk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	assert.Nil(t, err)
	sig, err := cryptoutils.Sign(pk, message)
	assert.Nil(t, err)
	encoded, err := EncodeSignature(sig)
	assert.Nil(t, err)
	assert.NotNil(t, encoded)
	parsed, err := ParseSignature(encoded, pk.Public)
	assert.Nil(t, err)
	assert.NotNil(t, parsed)
	assert.Equal(t, sig, parsed)
}

func Test_EncodeSignature_SuccessEcdsaS256(t *testing.T) {
	message := []byte("somedata")
	pk, err := ecdsa.GenerateKey(cryptoutils.S256(), rand.Reader)
	assert.Nil(t, err)
	sig, err := cryptoutils.Sign(pk, message)
	assert.Nil(t, err)
	encoded, err := EncodeSignature(sig)
	assert.Nil(t, err)
	assert.NotNil(t, encoded)
	parsed, err := ParseSignature(encoded, pk.Public)
	assert.Nil(t, err)
	assert.NotNil(t, parsed)
	assert.Equal(t, sig, parsed)
}

func Test_EncodeSignature_FailureUnknownType(t *testing.T) {
	bad := []byte("bad")
	sig := NewTestSignature(bad)
	encoded, err := EncodeSignature(sig)
	assert.Equal(t, "", encoded)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unknown signature type")
	assert.Contains(t, err.Error(), "("+string(bad)+")")
}

func Test_EncodeSignatureEcdsaUnsupportedCurveP224(t *testing.T) {
	message := []byte("somedata")
	pk, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	assert.Nil(t, err)
	sig, err := cryptoutils.Sign(pk, message)
	assert.Nil(t, err)
	encoded, err := EncodeSignature(sig)
	assert.Nil(t, err)
	assert.NotNil(t, encoded)
	_, err = ParseSignature(encoded, pk.Public)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "unknown signature type")
}
