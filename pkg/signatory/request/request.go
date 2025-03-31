package request

import (
	tz "github.com/ecadlabs/gotez/v2"
	"github.com/ecadlabs/gotez/v2/crypt"
	"github.com/ecadlabs/gotez/v2/protocol"
)

type WithWatermark interface {
	protocol.SignRequest
	GetChainID() *tz.ChainID
	GetLevel() int32
	GetRound() int32
}

type Watermark struct {
	Level int32                          `json:"level"`
	Round int32                          `json:"round"`
	Hash  tz.Option[tz.BlockPayloadHash] `json:"hash"`
}

func NewWatermark(req WithWatermark, hash *crypt.Digest) *Watermark {
	return &Watermark{
		Level: req.GetLevel(),
		Round: req.GetRound(),
		Hash:  tz.Some((tz.BlockPayloadHash)(*hash)),
	}
}

// Validate compares watermarks to prevent double signing.
// We intentionally don't consider hash equality, as that would allow two instances to sign the same block.
func (l *Watermark) Validate(stored *Watermark) bool {
	var diff int32
	if d := l.Level - stored.Level; d == 0 {
		diff = l.Round - stored.Round
	} else {
		diff = d
	}
	return diff > 0
}

var (
	_ WithWatermark = (*protocol.BlockSignRequest)(nil)
	_ WithWatermark = (*protocol.PreendorsementSignRequest)(nil)
	_ WithWatermark = (*protocol.EndorsementSignRequest)(nil)
)
