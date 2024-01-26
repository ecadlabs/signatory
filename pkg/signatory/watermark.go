package signatory

import (
	"github.com/ecadlabs/gotez/v2/crypt"
	"github.com/ecadlabs/gotez/v2/protocol"
)

// Watermark tests level against stored high watermark
type Watermark interface {
	IsSafeToSign(pkh crypt.PublicKeyHash, req protocol.SignRequest, digest *crypt.Digest) error
}

// IgnoreWatermark watermark that do not validation and return true
type IgnoreWatermark struct{}

// IsSafeToSign always return true
func (w IgnoreWatermark) IsSafeToSign(crypt.PublicKeyHash, protocol.SignRequest, *crypt.Digest) error {
	return nil
}

var _ Watermark = (*IgnoreWatermark)(nil)
