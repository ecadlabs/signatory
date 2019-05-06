package tezos

import (
	"errors"

	"github.com/ecadlabs/signatory/config"
)

// Magic Bytes of different operations
// According to: https://gitlab.com/tezos/tezos/blob/master/src/lib_crypto/signature.ml#L525
const (
	opMagicByteBlock       = 0x01
	opMagicByteEndorsement = 0x02
	opMagicByteGeneric     = 0x03
)

const (
	OpBlock       = "block"
	OpEndorsement = "endorsement"
	OpGeneric     = "generic"
)

var (
	// ErrMessageEmpty is an error indicating that a message was empty
	ErrMessageEmpty = errors.New("Message is empty")
	// ErrInvalidMagicByte is an error indicating that a message magic byte is invalid/
	ErrInvalidMagicByte = errors.New("Invalid magic byte")
	// ErrDoNotMatchFilter is an error indicating that a message magic byte is invalid/
	ErrDoNotMatchFilter = errors.New("Do not match filter")
)

// ValidateMessage validate if a tezos operation is valid
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

func FilterMessage(message []byte, conf *config.TezosConfig) error {
	if len(message) == 0 {
		return ErrDoNotMatchFilter
	}

	magicByteMap := map[byte]string{
		opMagicByteBlock:       OpBlock,
		opMagicByteEndorsement: OpEndorsement,
		opMagicByteGeneric:     OpGeneric,
	}

	magicByte := message[0]

	val, ok := magicByteMap[magicByte]

	if !ok {
		return ErrDoNotMatchFilter
	}

	for _, filter := range conf.AllowedOperations {
		if val == filter {
			return nil
		}
	}

	return ErrDoNotMatchFilter
}
