package mnemonic

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"testing"

	"github.com/ecadlabs/gotez/encoding"
	"github.com/ecadlabs/signatory/pkg/crypt"
	"github.com/stretchr/testify/assert"
)

var pubKey = []byte{0x30, 0x2a, 0x30, 0x5, 0x6, 0x3, 0x2b, 0x65, 0x70, 0x3, 0x21, 0x0, 0xbd, 0x5f, 0x29, 0xda, 0xb7, 0x86, 0x2, 0xff, 0xdb, 0x2b, 0x29, 0xa9, 0x9d, 0x2f, 0xad, 0xc5, 0xb0, 0x1d, 0x77, 0x86, 0xec, 0x43, 0xf1, 0x33, 0x3, 0x9b, 0x45, 0xa, 0xdf, 0xdd, 0x8d, 0xc2}

func TestMnemonic(t *testing.T) {
	// see tezos/src/lib_signer_backends/unix/test/test_crouching.ml
	x := New([]byte("12345"))
	assert.Equal(t, Mnemonic{"calculating", "meerkat", "straight", "beetle"}, x)

	pub, err := x509.ParsePKIXPublicKey(pubKey)
	assert.NoError(t, err)

	tzPub := crypt.Ed25519PublicKey(pub.(ed25519.PublicKey))

	var buf bytes.Buffer
	pkh := tzPub.Hash()
	// pass pointer to interface to preserve type information to encode correctly
	assert.NoError(t, encoding.Encode(&buf, &pkh))
	hash := buf.Bytes()
	x = New(hash)
	assert.Equal(t, Mnemonic{"zesty", "koala", "usable", "kiwi"}, x)
}
