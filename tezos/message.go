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
	// OpBlock config string for block operation
	OpBlock = "block"
	// OpEndorsement config string for endorsement operation
	OpEndorsement = "endorsement"
	// OpGeneric config string for generic operation
	OpGeneric = "generic"
	// OpUnknown config string for unkown operation
	OpUnknown = "unkown"
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

	msgType := GetMessageType(message)

	if msgType == OpUnknown {
		return ErrInvalidMagicByte
	}

	return nil
}

// GetMessageType return the message type
func GetMessageType(message []byte) string {
	if len(message) == 0 {
		return OpUnknown
	}

	magicByte := message[0]

	switch magicByte {
	case opMagicByteBlock:
		return OpBlock
	case opMagicByteEndorsement:
		return OpEndorsement
	case opMagicByteGeneric:
		return OpGeneric
	}

	return OpUnknown
}

// FilterMessage filter a message according to a Tezos Configuration
func FilterMessage(message []byte, conf *config.TezosConfig) error {
	msgType := GetMessageType(message)

	if msgType == OpUnknown {
		return ErrDoNotMatchFilter
	}

	for _, filter := range conf.AllowedOperations {
		if msgType == filter {
			return nil
		}
	}

	return ErrDoNotMatchFilter
}
