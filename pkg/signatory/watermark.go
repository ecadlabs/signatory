package signatory

import (
	"github.com/ecadlabs/signatory/pkg/tezos"
)

// Watermark tests level against stored high watermark
type Watermark interface {
	IsSafeToSign(pkh string, hash []byte, msg tezos.UnsignedMessage) error
}

// IgnoreWatermark watermark that do not validation and return true
type IgnoreWatermark struct{}

// IsSafeToSign always return true
func (w IgnoreWatermark) IsSafeToSign(pkh string, hash []byte, msg tezos.UnsignedMessage) error {
	return nil
}

var _ Watermark = (*IgnoreWatermark)(nil)
