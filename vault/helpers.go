package vault

import "math/big"

// Convert the X and Y coordinate to a compress format
// By the nature of elliptic curve for a given X there is two Y possible
// The compressed for consist of a first byte indicating which Y was chosen
func toCompressedFormat(x []byte, y []byte) []byte {
	yInt := new(big.Int).SetBytes(y)
	two := new(big.Int).SetInt64(2)
	even := new(big.Int).Mod(yInt, two).CmpAbs(new(big.Int).SetInt64(0)) == 0

	pubKey := []byte{0x03} // Odd byte

	if even {
		pubKey = []byte{0x02} // Even byte
	}

	pubKey = append(pubKey, x...)
	return pubKey
}
