package tezos

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/ecadlabs/signatory/pkg/config"
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
	opKindReveal      = 0x07
	opKindTransaction = 0x08
	opKindDelegation  = 0x0A
)

const (
	// OpBlock config string for block operation
	OpBlock = "block"
	// OpEndorsement config string for endorsement operation
	OpEndorsement = "endorsement"
	// OpGeneric config string for generic operation
	OpGeneric = "generic"
	// OpUnknown config string for unkown operation
	OpUnknown = "unknown"
)

const (
	// OpGenDelegation config string for delegation operation
	OpGenDelegation = "delegation"
	// OpGenReveal config string for reveal operation
	OpGenReveal = "reveal"
	// OpGenTransaction config string for transaction operation
	OpGenTransaction = "transaction"
	// OpGenProposal config string for proposal operation
	OpGenProposal = "proposal"
	// OpGenBallot config string for ballot operation
	OpGenBallot = "ballot"
	// OpGenUnknown config string for unknown operation
	OpGenUnknown = "unknown"
)

var (
	// ErrMessageTooShort is an error indicating that a message is too short
	ErrMessageTooShort = errors.New("Message is too short")
	// ErrDoNotMatchFilter is an error indicating that a message magic byte is invalid/
	ErrDoNotMatchFilter = errors.New("Operation not permitted by filter")
)

var opMagicBytes = map[int]string{
	opMagicByteBlock:       OpBlock,
	opMagicByteEndorsement: OpEndorsement,
	opMagicByteGeneric:     OpGeneric,
}

var kindsMagicBytes = map[int]string{
	opKindBallot:      OpGenBallot,
	opKindProposals:   OpGenProposal,
	opKindTransaction: OpGenTransaction,
	opKindReveal:      OpGenReveal,
	opKindDelegation:  OpGenDelegation,
}

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
	b := m.magicByte()
	if b < 0 {
		return ErrMessageTooShort
	}
	if _, ok := opMagicBytes[b]; !ok {
		return fmt.Errorf("Invalid magic byte: %#02x", b)
	}

	b = m.kindByte()
	if b < 0 {
		return ErrMessageTooShort
	}
	if _, ok := kindsMagicBytes[b]; !ok {
		return fmt.Errorf("Invalid kind code: %#02x", b)
	}

	return nil
}

func (m *Message) magicByte() int {
	if len(m.hex) == 0 {
		return -1
	}
	return int(m.hex[0])
}

// Type return the message type
func (m *Message) Type() string {
	b := m.magicByte()
	if b < 0 {
		return OpUnknown
	}

	if op, ok := opMagicBytes[b]; ok {
		return op
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
		return "unknown"
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

func (m *Message) kindByte() int {
	if len(m.hex) <= 33 {
		return -1
	}
	return int(m.hex[33])
}

// Kind return the kind of a generic operation
func (m *Message) Kind() string {
	b := m.kindByte()
	if b < 0 {
		return OpGenUnknown
	}

	if kind, ok := kindsMagicBytes[b]; ok {
		return kind
	}

	return OpGenUnknown
}

// MatchFilter filter a message according to a Tezos Configuration
func (m *Message) MatchFilter(conf *config.TezosPolicy) error {
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

	if !allowed {
		return ErrDoNotMatchFilter
	}

	// Generic operations have an extra check
	if msgType == OpGeneric {
		allowed = false
		kind := m.Kind()
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
