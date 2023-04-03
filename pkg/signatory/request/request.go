package request

import (
	tz "github.com/ecadlabs/gotez"
	"github.com/ecadlabs/gotez/encoding"
	"github.com/ecadlabs/gotez/protocol"
)

type SignRequest interface {
	RequestKind() string
}

type EmmyBlockRequest struct {
	Chain       *tz.ChainID
	BlockHeader protocol.ShellHeader
}

func (*EmmyBlockRequest) RequestKind() string { return "block" }

type TenderbakeBlockRequest struct {
	Chain       *tz.ChainID
	BlockHeader protocol.TenderbakeBlockHeader
}

func (*TenderbakeBlockRequest) RequestKind() string { return "block" }

type EmmyEndorsementRequest struct {
	Chain     *tz.ChainID
	Branch    *tz.BlockHash
	Operation protocol.InlinedEmmyEndorsementContents
}

func (*EmmyEndorsementRequest) RequestKind() string { return "endorsement" }

type PreendorsementRequest struct {
	Chain     *tz.ChainID
	Branch    *tz.BlockHash
	Operation protocol.InlinedPreendorsementContents
}

func (*PreendorsementRequest) RequestKind() string { return "preendorsement" }

type EndorsementRequest struct {
	Chain     *tz.ChainID
	Branch    *tz.BlockHash
	Operation protocol.InlinedEndorsementContents
}

func (*EndorsementRequest) RequestKind() string { return "endorsement" }

type GenericOperationRequest struct {
	Branch     *tz.BlockHash
	Operations []protocol.OperationContents
}

func (*GenericOperationRequest) RequestKind() string { return "generic" }

func init() {
	encoding.RegisterEnum(&encoding.Enum[SignRequest]{
		Variants: encoding.Variants[SignRequest]{
			0x01: (*EmmyBlockRequest)(nil),
			0x02: (*EmmyEndorsementRequest)(nil),
			0x03: (*GenericOperationRequest)(nil),
			0x11: (*TenderbakeBlockRequest)(nil),
			0x12: (*PreendorsementRequest)(nil),
			0x13: (*EndorsementRequest)(nil),
		},
	})
}

type WithWatermark interface {
	SignRequest
	Watermark() *Watermark
}

const (
	WmOrderDefault = iota
	WmOrderPreendorsement
	WmOrderEndorsement
)

type Level struct {
	Level int32            `json:"level"`
	Round tz.Option[int32] `json:"round"`
}

func (l *Level) Cmp(other *Level) tz.Option[int] {
	if l.Round.IsNone() && other.Round.IsSome() {
		return tz.None[int]()
	}

	if d := l.Level - other.Level; d == 0 {
		switch {
		case l.Round.IsSome() && other.Round.IsSome():
			return tz.Some(int(l.Round.Unwrap() - other.Round.Unwrap()))
		case l.Round.IsSome() && other.Round.IsNone():
			return tz.Some(1)
		default:
			return tz.Some(0)
		}
	} else {
		return tz.Some(int(d))
	}
}

type Watermark struct {
	Level
	Chain *tz.ChainID
	Order int
}

type StoredWatermark struct {
	Level
	Order int `json:"order"`
}

func (w *Watermark) Stored() *StoredWatermark {
	return &StoredWatermark{
		Level: w.Level,
		Order: w.Order,
	}
}

func (w *Watermark) Validate(stored *StoredWatermark) bool {
	c := w.Level.Cmp(&stored.Level)
	return c.IsSome() && (c.Unwrap() > 0 || c.Unwrap() == 0 && w.Order > stored.Order)
}

func (r *EmmyBlockRequest) Watermark() *Watermark {
	return &Watermark{
		Chain: r.Chain,
		Level: Level{
			Level: r.BlockHeader.Level,
			Round: tz.None[int32](),
		},
		Order: WmOrderDefault,
	}
}

func (r *TenderbakeBlockRequest) Watermark() *Watermark {
	return &Watermark{
		Chain: r.Chain,
		Level: Level{
			Level: r.BlockHeader.Level,
			Round: tz.Some(r.BlockHeader.PayloadRound),
		},
		Order: WmOrderDefault,
	}
}

func (r *EmmyEndorsementRequest) Watermark() *Watermark {
	return &Watermark{
		Chain: r.Chain,
		Level: Level{
			Level: r.Operation.(*protocol.EmmyEndorsement).Level,
			Round: tz.None[int32](),
		},
		Order: WmOrderEndorsement,
	}
}

func (r *PreendorsementRequest) Watermark() *Watermark {
	return &Watermark{
		Chain: r.Chain,
		Level: Level{
			Level: r.Operation.(*protocol.Preendorsement).Level,
			Round: tz.Some(r.Operation.(*protocol.Preendorsement).Round),
		},
		Order: WmOrderPreendorsement,
	}
}

func (r *EndorsementRequest) Watermark() *Watermark {
	return &Watermark{
		Chain: r.Chain,
		Level: Level{
			Level: r.Operation.(*protocol.Endorsement).Level,
			Round: tz.Some(r.Operation.(*protocol.Endorsement).Round),
		},
		Order: WmOrderEndorsement,
	}
}

var (
	_ WithWatermark = (*EmmyBlockRequest)(nil)
	_ WithWatermark = (*EmmyEndorsementRequest)(nil)
	_ WithWatermark = (*TenderbakeBlockRequest)(nil)
	_ WithWatermark = (*PreendorsementRequest)(nil)
	_ WithWatermark = (*EndorsementRequest)(nil)
)
