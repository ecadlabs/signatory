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
