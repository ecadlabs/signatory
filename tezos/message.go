package tezos

import (
	"errors"
	"fmt"
	"math/big"

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
	opKindUnknown     = 0xff
	opKindProposals   = 0x05
	opKindBallot      = 0x06
	opKindTransaction = 0x08
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

const (
	// OpGenTransaction config string for transaction operation
	OpGenTransaction = "transaction"
	// OpGenProposal config string for proposal operation
	OpGenProposal = "proposal"
	// OpGenBallot config string for ballot operation
	OpGenBallot = "ballot"
	// OpGenUnknown config string for unknown operation
	OpGenUnknown = "unkown"
)

var (
	// ErrMessageEmpty is an error indicating that a message was empty
	ErrMessageEmpty = errors.New("Message is empty")
	// ErrInvalidMagicByte is an error indicating that a message magic byte is invalid/
	ErrInvalidMagicByte = errors.New("Invalid magic byte")
	// ErrDoNotMatchFilter is an error indicating that a message magic byte is invalid/
	ErrDoNotMatchFilter = errors.New("Operation not permitted by filter")
)

// Message represent a tezos message
type Message struct {
	hex []byte
}

// ParseMessage parse a tezos message
func ParseMessage(message []byte) *Message {
	return &Message{message}
}

// Validate validate if a tezos operation is valid
func (m *Message) Validate() error {
	if len(m.hex) == 0 {
		return ErrMessageEmpty
	}

	if m.Type() == OpUnknown {
		return ErrInvalidMagicByte
	}

	return nil
}

// Type return the message type
func (m *Message) Type() string {
	if len(m.hex) == 0 {
		return OpUnknown
	}

	magicByte := m.hex[0]

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

// RequireWatermark return true if this message must be watermarked
func (m *Message) RequireWatermark() bool {
	if m.Type() == OpBlock || m.Type() == OpEndorsement {
		return true
	}
	return false
}

// Watermark create a tezos watermark
func (m *Message) Watermark(keyHash string) (string, *big.Int) {
	msgID := fmt.Sprintf("%s:%s:%s", keyHash, m.chainID(), m.Type())
	return msgID, m.level()
}

func (m *Message) chainID() string {
	if len(m.hex) < 6 {
		return "unkown"
	}

	chainID := m.hex[1:5]
	return base58CheckEncodePrefix(chainIDPrefix, chainID)
}

func (m *Message) level() *big.Int {
	if len(m.hex) < 10 {
		return nil
	}

	msgType := m.Type()
	if msgType == OpBlock {
		return new(big.Int).SetBytes(m.hex[5:9])
	} else if msgType == OpEndorsement {
		return new(big.Int).SetBytes(m.hex[len(m.hex)-4:])
	}
	return nil
}

func (m *Message) kind() string {
	if len(m.hex) <= 33 {
		return OpGenUnknown
	}

	kind := m.hex[33]

	switch kind {
	case opKindBallot:
		return OpGenBallot
	case opKindProposals:
		return OpGenProposal
	case opKindTransaction:
		return OpGenTransaction
	default:
		return OpGenUnknown
	}
}

// MatchFilter filter a message according to a Tezos Configuration
func (m *Message) MatchFilter(conf *config.TezosConfig) error {
	msgType := m.Type()

	if msgType == OpUnknown {
		return ErrDoNotMatchFilter
	}

	var allowed = false

	for _, filter := range conf.AllowedOperations {
		if msgType == filter {
			allowed = true
		}
	}

	// Generic operations have an extra check
	if msgType == OpGeneric {
		allowed = false
		kind := m.kind()
		for _, filter := range conf.AllowedKinds {
			if kind == filter {
				allowed = true
			}
		}
	}

	if !allowed {
		return ErrDoNotMatchFilter
	}

	return nil
}
