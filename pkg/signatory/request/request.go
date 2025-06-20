package request

import (
	tz "github.com/ecadlabs/gotez/v2"
	"github.com/ecadlabs/gotez/v2/crypt"
	"github.com/ecadlabs/gotez/v2/protocol/core"
	proto "github.com/ecadlabs/gotez/v2/protocol/latest"
)

type WithWatermark interface {
	core.SignRequest
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

func (l *Watermark) Validate(stored *Watermark) bool {
	if l.Hash.IsSome() && stored.Hash.IsSome() && l.Hash.Unwrap() == stored.Hash.Unwrap() {
		return true
	}
	var diff int32
	if d := l.Level - stored.Level; d == 0 {
		diff = l.Round - stored.Round
	} else {
		diff = d
	}
	return diff > 0
}

var (
	_ WithWatermark = (*proto.BlockSignRequest)(nil)
	_ WithWatermark = (*proto.PreattestationSignRequest)(nil)
	_ WithWatermark = (*proto.AttestationSignRequest)(nil)
)
