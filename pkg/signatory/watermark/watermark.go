package watermark

import (
	"github.com/ecadlabs/gotez/v2/crypt"
	"github.com/ecadlabs/gotez/v2/protocol"
)

// Watermark tests level against stored high watermark
type Watermark interface {
	IsSafeToSign(pkh crypt.PublicKeyHash, req protocol.SignRequest, digest *crypt.Digest) error
}

// Ignore watermark that do not validation and return true
type Ignore struct{}

// IsSafeToSign always return true
func (w Ignore) IsSafeToSign(crypt.PublicKeyHash, protocol.SignRequest, *crypt.Digest) error {
	return nil
}

var _ Watermark = (*Ignore)(nil)
