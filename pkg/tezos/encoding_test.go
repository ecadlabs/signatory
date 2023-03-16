package tezos

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// NetXzfS4qFhir8c
func Test_DecodeChainID_Success4Bytes(t *testing.T) {
	str := "c4c56423"
	res, err := DecodeChainID(str)
	require.Nil(t, err)
	require.NotEqual(t, "", res)
	assert.Equal(t, 4, len(res))
	str1 := hex.EncodeToString(res[:])
	assert.Equal(t, str, str1)
}

func Test_DecodeChainID_FailWrongLength(t *testing.T) {
	b := []byte{1, 2, 3, 4, 5}
	str := hex.EncodeToString(b)
	_, err := DecodeChainID(str)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "invalid chain ID")
}

func Test_EncodeValueHash_Success(t *testing.T) {
	b := []byte{0, 1, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32}
	res := EncodeValueHash(b)
	require.NotNil(t, res)
	b1, err := DecodeValueHash(res)
	require.Nil(t, err)
	for i, _ := range b {
		assert.Equal(t, b[i], b1[i])
	}
}

func Test_DecodeValueHash_FailInvalidChar(t *testing.T) {
	_, err := DecodeValueHash("101")
	require.NotNil(t, err)
	assert.Contains(t, err.Error(), "invalid character 0 at position 1")
}
