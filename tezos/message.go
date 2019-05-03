package tezos

import "errors"

// Magic Bytes of different operations
// According to: https://gitlab.com/tezos/tezos/blob/master/src/lib_crypto/signature.ml#L525
const (
	opMagicByteBlock       = 0x01
	opMagicByteEndorsement = 0x02
	opMagicByteGeneric     = 0x03
)

var (
	ErrMessageEmpty     = errors.New("Message is empty")
	ErrInvalidMagicByte = errors.New("Invalid magic byte")
)

func ValidateMessage(message []byte) error {
	if len(message) == 0 {
		return ErrMessageEmpty
	}

	magicByte := message[0]

	if magicByte == 0 || magicByte > opMagicByteGeneric {
		return ErrInvalidMagicByte
	}

	return nil
}
