package mnemonic

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMnemonic(t *testing.T) {
	// see tezos/src/lib_signer_backends/unix/test/test_crouching.ml
	x := GenerateMnemonic([]byte("12345"))
	assert.Equal(t, Mnemonic{"calculating", "meerkat", "straight", "beetle"}, x)
}
