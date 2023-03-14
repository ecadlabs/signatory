package signatory

import (
	"github.com/ecadlabs/signatory/pkg/signatory/request"
)

// Watermark tests level against stored high watermark
type Watermark interface {
	IsSafeToSign(pkh string, req request.SignRequest) error
}

// IgnoreWatermark watermark that do not validation and return true
type IgnoreWatermark struct{}

// IsSafeToSign always return true
func (w IgnoreWatermark) IsSafeToSign(pkh string, req request.SignRequest) error {
	return nil
}

var _ Watermark = (*IgnoreWatermark)(nil)
