package tezos

import (
	"fmt"
	"time"

	"github.com/ecadlabs/signatory/pkg/tezos/utils"
)

// UnsignedMessage is implemented by all kinds of sign request payloads
type UnsignedMessage interface {
	MessageKind() string
}

// MessageWithLevel is implemented by UnsignedBlockHeader and UnsignedEndorsement. Useful for high water marking.
type MessageWithLevel interface {
	UnsignedMessage
	GetChainID() string
	GetLevel() int32
}

type MessageWithRound interface {
	MessageWithLevel
	GetRound() int32
}

// GenericOperationRequest represents operation without a signature
type GenericOperationRequest struct {
	Branch   string
	Contents []Operation
}

// OperationKinds returns list of uperation kinds
func (u *GenericOperationRequest) OperationKinds() []string {
	ops := make([]string, len(u.Contents))
	for i, o := range u.Contents {
		ops[i] = o.OperationKind()
	}
	return ops
}

// MessageKind returns unsigned message kind name i.e. "generic"
func (u *GenericOperationRequest) MessageKind() string { return "generic" }

func parseGenericOperationRequest(buf *[]byte) (*GenericOperationRequest, error) {
	blockHash, err := utils.GetBytes(buf, 32)
	if err != nil {
		return nil, err
	}
	var ops []Operation
	for len(*buf) != 0 {
		op, err := parseOperation(buf)
		if err != nil {
			return nil, err
		}
		ops = append(ops, op)
	}
	return &GenericOperationRequest{
		Branch:   encodeBase58(pBlockHash, blockHash),
		Contents: ops,
	}, nil
}

type ShellBlockHeader struct {
	Level          int32
	Proto          byte
	Predecessor    string
	Timestamp      time.Time
	ValidationPass byte
	OperationsHash string
	Fitness        [][]byte
	Context        string
}

// GetLevel returns block level
func (b *ShellBlockHeader) GetLevel() int32 { return b.Level }

func parseShellBlockHeader(buf *[]byte) (*ShellBlockHeader, error) {
	var (
		b   ShellBlockHeader
		err error
	)
	if b.Level, err = utils.GetInt32(buf); err != nil {
		return nil, err
	}
	if b.Proto, err = utils.GetByte(buf); err != nil {
		return nil, err
	}
	hash, err := utils.GetBytes(buf, 32)
	if err != nil {
		return nil, err
	}
	b.Predecessor = encodeBase58(pBlockHash, hash)
	ts, err := utils.GetInt64(buf)
	if err != nil {
		return nil, err
	}
	b.Timestamp = time.Unix(ts, 0).UTC()
	if b.ValidationPass, err = utils.GetByte(buf); err != nil {
		return nil, err
	}
	if hash, err = utils.GetBytes(buf, 32); err != nil {
		return nil, err
	}
	b.OperationsHash = encodeBase58(pOperationListListHash, hash)
	ln, err := utils.GetUint32(buf)
	if err != nil {
		return nil, err
	}
	fbuf, err := utils.GetBytes(buf, int(ln))
	if err != nil {
		return nil, err
	}
	for len(fbuf) != 0 {
		ln, err := utils.GetUint32(&fbuf)
		if err != nil {
			return nil, err
		}
		elem, err := utils.GetBytes(&fbuf, int(ln))
		if err != nil {
			return nil, err
		}
		b.Fitness = append(b.Fitness, elem)
	}
	if hash, err = utils.GetBytes(buf, 32); err != nil {
		return nil, err
	}
	b.Context = encodeBase58(pContextHash, hash)
	return &b, nil
}

const (
	lbVoteOn = iota
	lbVoteOff
	lbVotePass
)

// BlockHeader represents unsigned block header
type BlockHeader struct {
	ShellBlockHeader
	PayloadHash               string
	PayloadRound              int32
	ProofOfWorkNonce          []byte
	SeedNonceHash             string
	LiquidityBakingToggleVote string
}

func (b *BlockHeader) GetRound() int32 {
	return b.PayloadRound
}

func parseUnsignedBlockHeader(buf *[]byte) (*BlockHeader, error) {
	sh, err := parseShellBlockHeader(buf)
	if err != nil {
		return nil, err
	}
	b := BlockHeader{
		ShellBlockHeader: *sh,
	}
	hash, err := utils.GetBytes(buf, 32)
	if err != nil {
		return nil, err
	}
	b.PayloadHash = encodeBase58(pValueHash, hash)
	if b.PayloadRound, err = utils.GetInt32(buf); err != nil {
		return nil, err
	}
	if b.ProofOfWorkNonce, err = utils.GetBytes(buf, 8); err != nil {
		return nil, err
	}
	flag, err := utils.GetBool(buf)
	if err != nil {
		return nil, err
	}
	if flag {
		hash, err := utils.GetBytes(buf, 32)
		if err != nil {
			return nil, err
		}
		b.SeedNonceHash = encodeBase58(pCycleNonce, hash)
	}
	vote, err := utils.GetByte(buf)
	if err != nil {
		return nil, err
	}
	switch vote {
	case lbVoteOn:
		b.LiquidityBakingToggleVote = "on"
	case lbVoteOff:
		b.LiquidityBakingToggleVote = "off"
	case lbVotePass:
		b.LiquidityBakingToggleVote = "pass"
	default:
		return nil, fmt.Errorf("invalid liquidity baking vote: %d", vote)
	}
	return &b, nil
}

// TenderbakeBlockRequest represents unsigned block header
type TenderbakeBlockRequest struct {
	ChainID string
	*BlockHeader
}

// MessageKind returns unsigned message kind name i.e. "block"
func (t *TenderbakeBlockRequest) MessageKind() string { return "block" }

// GetChainID returns chain ID
func (t *TenderbakeBlockRequest) GetChainID() string { return t.ChainID }

type EmmyBlockRequest struct {
	ChainID           string
	*ShellBlockHeader // skip Emmy protocol data for convenience
}

// MessageKind returns unsigned message kind name i.e. "block"
func (e *EmmyBlockRequest) MessageKind() string { return "block" }

// GetChainID returns chain ID
func (e *EmmyBlockRequest) GetChainID() string { return e.ChainID }

// EmmyEndorsementRequest represents unsigned endorsement
type EmmyEndorsementRequest struct {
	ChainID string
	Branch  string
	*OpEmmyEndorsement
}

// GetChainID returns chain ID
func (e *EmmyEndorsementRequest) GetChainID() string  { return e.ChainID }
func (e *EmmyEndorsementRequest) MessageKind() string { return "endorsement" }

// TenderbakeEndorsementRequest represents unsigned endorsement
type TenderbakeEndorsementRequest struct {
	ChainID string
	Branch  string
	*OpTenderbakeEndorsement
}

// GetChainID returns chain ID
func (t *TenderbakeEndorsementRequest) GetChainID() string  { return t.ChainID }
func (t *TenderbakeEndorsementRequest) MessageKind() string { return "endorsement" }

func parseEmmyEndorsementRequest(buf *[]byte) (*EmmyEndorsementRequest, error) {
	chainID, err := utils.GetBytes(buf, 4)
	if err != nil {
		return nil, err
	}
	blockHash, err := utils.GetBytes(buf, 32)
	if err != nil {
		return nil, err
	}
	op, err := parseOperation(buf)
	if err != nil {
		return nil, err
	}
	e, ok := op.(*OpEmmyEndorsement)
	if !ok {
		return nil, fmt.Errorf("tezos: endorsement operation expected, got: %T", op)
	}
	return &EmmyEndorsementRequest{
		ChainID:           encodeBase58(pChainID, chainID),
		Branch:            encodeBase58(pBlockHash, blockHash),
		OpEmmyEndorsement: e,
	}, nil
}

func parseTenderbakeEndorsementRequest(buf *[]byte) (*TenderbakeEndorsementRequest, error) {
	chainID, err := utils.GetBytes(buf, 4)
	if err != nil {
		return nil, err
	}
	blockHash, err := utils.GetBytes(buf, 32)
	if err != nil {
		return nil, err
	}
	op, err := parseOperation(buf)
	if err != nil {
		return nil, err
	}
	e, ok := op.(*OpTenderbakeEndorsement)
	if !ok {
		return nil, fmt.Errorf("tezos: endorsement operation expected, got: %T", op)
	}
	return &TenderbakeEndorsementRequest{
		ChainID:                 encodeBase58(pChainID, chainID),
		Branch:                  encodeBase58(pBlockHash, blockHash),
		OpTenderbakeEndorsement: e,
	}, nil
}

// PreendorsementRequest represents unsigned preendorsement
type PreendorsementRequest struct {
	ChainID string
	Branch  string
	*OpPreendorsement
}

// MessageKind returns unsigned message kind name i.e. "preendorsement"
func (u *PreendorsementRequest) MessageKind() string { return "preendorsement" }

// GetChainID returns chain ID
func (u *PreendorsementRequest) GetChainID() string { return u.ChainID }

func parsePreendorsementRequest(buf *[]byte) (*PreendorsementRequest, error) {
	chainID, err := utils.GetBytes(buf, 4)
	if err != nil {
		return nil, err
	}
	blockHash, err := utils.GetBytes(buf, 32)
	if err != nil {
		return nil, err
	}
	op, err := parseOperation(buf)
	if err != nil {
		return nil, err
	}
	e, ok := op.(*OpPreendorsement)
	if !ok {
		return nil, fmt.Errorf("tezos: preendorsement operation expected, got: %T", op)
	}
	return &PreendorsementRequest{
		ChainID:          encodeBase58(pChainID, chainID),
		Branch:           encodeBase58(pBlockHash, blockHash),
		OpPreendorsement: e,
	}, nil
}

const (
	magicEmmyBlock             = 0x01
	magicEmmyEndorsement       = 0x02
	magicGenericOperation      = 0x03
	magicTenderbakeBlock       = 0x11
	magicPreendorsement        = 0x12
	magicTenderbakeEndorsement = 0x13
)

func parseRequest(buf *[]byte) (u UnsignedMessage, err error) {
	t, err := utils.GetByte(buf)
	if err != nil {
		return nil, err
	}

	switch t {
	case magicEmmyBlock:
		b, err := utils.GetBytes(buf, 4)
		if err != nil {
			return nil, err
		}
		bh, err := parseShellBlockHeader(buf) // skip Emmy protocol data
		if err != nil {
			return nil, err
		}
		return &EmmyBlockRequest{
			ChainID:          encodeBase58(pChainID, b),
			ShellBlockHeader: bh,
		}, nil

	case magicTenderbakeBlock:
		b, err := utils.GetBytes(buf, 4)
		if err != nil {
			return nil, err
		}
		bh, err := parseUnsignedBlockHeader(buf)
		if err != nil {
			return nil, err
		}
		return &TenderbakeBlockRequest{
			ChainID:     encodeBase58(pChainID, b),
			BlockHeader: bh,
		}, nil

	case magicEmmyEndorsement:
		return parseEmmyEndorsementRequest(buf)

	case magicPreendorsement:
		return parsePreendorsementRequest(buf)

	case magicTenderbakeEndorsement:
		return parseTenderbakeEndorsementRequest(buf)

	case magicGenericOperation:
		return parseGenericOperationRequest(buf)
	}
	return nil, fmt.Errorf("tezos: unknown watermark tag: %d", t)
}

// ParseRequest returns parsed sign request
func ParseRequest(data []byte) (u UnsignedMessage, err error) {
	var buf = data
	return parseRequest(&buf)
}

var (
	_ MessageWithLevel = (*EmmyBlockRequest)(nil)
	_ MessageWithLevel = (*EmmyEndorsementRequest)(nil)
	_ MessageWithRound = (*TenderbakeBlockRequest)(nil)
	_ MessageWithRound = (*TenderbakeEndorsementRequest)(nil)
	_ MessageWithRound = (*PreendorsementRequest)(nil)
)
