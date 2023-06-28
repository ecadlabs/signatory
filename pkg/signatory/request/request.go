package request

import (
	tz "github.com/ecadlabs/gotez"
	"github.com/ecadlabs/gotez/encoding"
	"github.com/ecadlabs/gotez/protocol"
	"github.com/ecadlabs/signatory/pkg/crypt"
)

type SignRequest interface {
	RequestKind() string
}

type BlockRequest struct {
	Chain       *tz.ChainID
	BlockHeader protocol.TenderbakeBlockHeader
}

func (*BlockRequest) RequestKind() string       { return "block" }
func (r *BlockRequest) GetChainID() *tz.ChainID { return r.Chain }
func (r *BlockRequest) GetLevel() int32         { return r.BlockHeader.Level }
func (r *BlockRequest) GetRound() int32         { return r.BlockHeader.PayloadRound }

type PreendorsementRequest struct {
	Chain     *tz.ChainID
	Branch    *tz.BlockHash
	Operation protocol.InlinedPreendorsementContents
}

func (*PreendorsementRequest) RequestKind() string       { return "preendorsement" }
func (r *PreendorsementRequest) GetChainID() *tz.ChainID { return r.Chain }
func (r *PreendorsementRequest) GetLevel() int32         { return r.Operation.(*protocol.Preendorsement).Level }
func (r *PreendorsementRequest) GetRound() int32         { return r.Operation.(*protocol.Preendorsement).Round }

type EndorsementRequest struct {
	Chain     *tz.ChainID
	Branch    *tz.BlockHash
	Operation protocol.InlinedEndorsementContents
}

func (*EndorsementRequest) RequestKind() string       { return "endorsement" }
func (r *EndorsementRequest) GetChainID() *tz.ChainID { return r.Chain }
func (r *EndorsementRequest) GetLevel() int32         { return r.Operation.(*protocol.Endorsement).Level }
func (r *EndorsementRequest) GetRound() int32         { return r.Operation.(*protocol.Endorsement).Round }

type GenericOperationRequest struct {
	Branch     *tz.BlockHash
	Operations []protocol.OperationContents
}

func (*GenericOperationRequest) RequestKind() string { return "generic" }

func init() {
	encoding.RegisterEnum(&encoding.Enum[SignRequest]{
		Variants: encoding.Variants[SignRequest]{
			0x03: (*GenericOperationRequest)(nil),
			0x11: (*BlockRequest)(nil),
			0x12: (*PreendorsementRequest)(nil),
			0x13: (*EndorsementRequest)(nil),
		},
	})
}

type WithWatermark interface {
	SignRequest
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
	_ WithWatermark = (*BlockRequest)(nil)
	_ WithWatermark = (*PreendorsementRequest)(nil)
	_ WithWatermark = (*EndorsementRequest)(nil)
)
