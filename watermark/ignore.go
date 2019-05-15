package watermark

import (
	"math/big"
)

// Ignore watermark that do not validation and return true
type Ignore struct {
}

// NewIgnore create a new ignore watermark
func NewIgnore() *Ignore {
	return &Ignore{}
}

// IsSafeToSign always return true
func (w *Ignore) IsSafeToSign(msgID string, level *big.Int) bool {
	return true
}
