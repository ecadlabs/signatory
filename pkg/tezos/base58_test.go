package tezos

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_Decode_Success(t *testing.T) {
	input := "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz123456789"
	d, err := DecodeBase58(input)
	require.Nil(t, err)
	assert.Equal(t, 43, len(d))
	e := EncodeBase58(d)
	assert.Equal(t, input, e)
}

func Test_Decode_AlphabetBoundaries(t *testing.T) {
	input := "AHJNPZakm19" //each of these characters is a valid character that is adjacent to an invalid character in ascii table
	d, err := DecodeBase58(input)
	require.Nil(t, err)
	assert.Equal(t, 8, len(d))
	e := EncodeBase58(d)
	assert.Equal(t, input, e)
}

func Test_Decode_InvalidCharacters(t *testing.T) {
	invalid := `0lIO~!@#$%^&*()-_=+\|[]{}'";:/?,.<>`
	valid := "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz123456789"
	for index, c := range invalid {
		input := valid[:index] + string(c) + valid[index:]
		_, err := DecodeBase58(input)
		require.NotNil(t, err)
		assert.Contains(t, err.Error(), fmt.Sprintf("base58 decoding error: invalid character %s at position %d", string(c), index))
	}
}

func Test_Encode_LeadingZeros(t *testing.T) {
	b := []byte{0, 0, 102, 97, 108, 99, 111, 110}
	s := EncodeBase58(b)
	assert.Equal(t, "1", string(s[0]))
	assert.Equal(t, "1", string(s[1]))
	d, err := DecodeBase58(string(s))
	require.Nil(t, err)
	assert.Equal(t, uint8(0x0), d[0])
	assert.Equal(t, uint8(0x0), d[1])
	assert.Equal(t, string(b), string(d))
}

func Test_Decode_InvalidCharAfterLeadingZeros(t *testing.T) {
	input := "1abcIdef"
	_, err := DecodeBase58(input)
	require.NotNil(t, err)
	assert.Contains(t, err.Error(), "base58 decoding error: invalid character I at position 4")
}

func Test_DecodeCheck_FailsMin4Bytes(t *testing.T) {
	input := "ABCD"
	_, err := DecodeBase58Check(input)
	require.NotNil(t, err)
	assert.Equal(t, "base58Check decoding error: data is too short: 3", err.Error())
}

func Test_DecodeCheck_FailsInvalidChecksum(t *testing.T) {
	input := "ABCDE"
	_, err := DecodeBase58Check(input)
	require.NotNil(t, err)
	assert.Equal(t, "base58Check decoding error: invalid checksum", err.Error())
}

func Test_DecodeCheck_FailsInvalidChar(t *testing.T) {
	input := "1abcIdef"
	_, err := DecodeBase58Check(input)
	require.NotNil(t, err)
	assert.Contains(t, err.Error(), "base58 decoding error: invalid character I at position 4")
}
