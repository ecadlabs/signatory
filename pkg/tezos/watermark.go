package tezos

import (
	"github.com/ecadlabs/signatory/pkg/crypt"
	"github.com/ecadlabs/signatory/pkg/tezos/request"
)

// Watermark tests level against stored high watermark
type Watermark interface {
	IsSafeToSign(pkh crypt.PublicKeyHash, req request.SignRequest, digest *crypt.Digest) error
}

// IgnoreWatermark watermark that do not validation and return true
type IgnoreWatermark struct{}

// IsSafeToSign always return true
func (w IgnoreWatermark) IsSafeToSign(crypt.PublicKeyHash, request.SignRequest, *crypt.Digest) error {
	return nil
}

var _ Watermark = (*IgnoreWatermark)(nil)
