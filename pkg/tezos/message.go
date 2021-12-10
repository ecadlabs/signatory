package tezos

import (
	"fmt"
	"math/big"
	"time"
)

const (
	tagOpEndorsement               = 0
	tagOpSeedNonceRevelation       = 1
	tagOpDoubleEndorsementEvidence = 2
	tagOpDoubleBakingEvidence      = 3
	tagOpActivateAccount           = 4
	tagOpProposals                 = 5
	tagOpBallot                    = 6
	tagOpEndorsementWithSlot       = 10
	tagOpReveal                    = 107
	tagOpTransaction               = 108
	tagOpOrigination               = 109
	tagOpDelegation                = 110
)

const (
	ballotYay = iota
	ballotNay
	ballotPass
)

// UnsignedMessage is implemented by all kinds of sign request payloads
type UnsignedMessage interface {
	MessageKind() string
}

// UnsignedOperation represents operation without a signature
type UnsignedOperation struct {
	Branch   string
	Contents []OperationContents
}

// MessageKind returns unsigned message kind name i.e. "generic"
func (u *UnsignedOperation) MessageKind() string { return "generic" }

// OperationKinds returns list of uperation kinds for logging purposes
func (u *UnsignedOperation) OperationKinds() []string {
	ops := make([]string, len(u.Contents))
	for i, o := range u.Contents {
		ops[i] = o.OperationKind()
	}
	return ops
}

// OperationContents is implemented by all operations
type OperationContents interface {
	OperationKind() string
}

// OpEndorsement represents "endorsement" operation
type OpEndorsement struct {
	Level int32
}

// GetLevel returns block level
func (o *OpEndorsement) GetLevel() int32 { return o.Level }

// OperationKind returns operation name i.e. "endorsement"
func (o *OpEndorsement) OperationKind() string { return "endorsement" }

// OpEndorsementWithSlot represents "endorsement" operation
type OpEndorsementWithSlot struct {
	InlinedEndorsement
	Slot uint16
}

// OperationKind returns operation name i.e. "endorsement_with_slot"
func (o *OpEndorsementWithSlot) OperationKind() string { return "endorsement_with_slot" }

// OpSeedNonceRevelation represents "seed_nonce_revelation" operation
type OpSeedNonceRevelation struct {
	Level int32
	Nonce []byte
}

// GetLevel returns block level
func (o *OpSeedNonceRevelation) GetLevel() int32 { return o.Level }

// OperationKind returns operation name i.e. "seed_nonce_revelation"
func (o *OpSeedNonceRevelation) OperationKind() string { return "seed_nonce_revelation" }

// InlinedEndorsement represents inlined endorsement operation with signature
type InlinedEndorsement struct {
	OpEndorsement
	Branch    string
	Signature string
}

// OpDoubleEndorsementEvidence represents "double_endorsement_evidence" operation
type OpDoubleEndorsementEvidence struct {
	Op1 *InlinedEndorsement
	Op2 *InlinedEndorsement
}

// OperationKind returns operation name i.e. "double_endorsement_evidence"
func (o *OpDoubleEndorsementEvidence) OperationKind() string { return "double_endorsement_evidence" }

// OpDoubleBakingEvidence represents "double_baking_evidence" operation
type OpDoubleBakingEvidence struct {
	BlockHeader1 *BlockHeader
	BlockHeader2 *BlockHeader
}

// OperationKind returns operation name i.e. "double_baking_evidence"
func (o *OpDoubleBakingEvidence) OperationKind() string { return "double_baking_evidence" }

// OpActivateAccount represents "activate_account" operation
type OpActivateAccount struct {
	PublicKeyHash string
	Secret        []byte
}

// OperationKind returns operation name i.e. "activate_account"
func (o *OpActivateAccount) OperationKind() string { return "activate_account" }

// OpBallot represents "ballot" operation
type OpBallot struct {
	Source   string
	Period   int32
	Proposal string
	Ballot   string
}

// OperationKind returns operation name i.e. "ballot"
func (o *OpBallot) OperationKind() string { return "ballot" }

// OpProposals represents "proposals" operation
type OpProposals struct {
	Source    string
	Period    int32
	Proposals []string
}

// OperationKind returns operation name i.e. "proposals"
func (o *OpProposals) OperationKind() string { return "proposals" }

// Manager has fields common for all manager operations
type Manager struct {
	Source       string
	Fee          *big.Int
	Counter      *big.Int
	GasLimit     *big.Int
	StorageLimit *big.Int
}

// OpReveal represents "reveal" operation
type OpReveal struct {
	Manager
	PublicKey string
}

// OperationKind returns operation name i.e. "reveal"
func (o *OpReveal) OperationKind() string { return "reveal" }

// OpTransaction represents "transaction" operation
type OpTransaction struct {
	Manager
	Amount      *big.Int
	Destination string
	Parameters  *TxParameters
}

// OperationKind returns operation name i.e. "transaction"
func (o *OpTransaction) OperationKind() string { return "transaction" }

// TxParameters represents transaction parameters
type TxParameters struct {
	Value      []byte
	Entrypoint string // post Babylon
}

// ScriptedContracts contains contract data
type ScriptedContracts struct {
	Code    []byte
	Storage []byte
}

// OpOrigination represents "origination" operation
type OpOrigination struct {
	Manager
	Balance  *big.Int
	Delegate string
	Script   *ScriptedContracts
}

// OperationKind returns operation name i.e. "origination"
func (o *OpOrigination) OperationKind() string { return "origination" }

// OpDelegation represents "delegation" operation
type OpDelegation struct {
	Manager
	Delegate string
}

// OperationKind returns operation name i.e. "delegation"
func (o *OpDelegation) OperationKind() string { return "delegation" }

func parseOperation(buf *[]byte) (op OperationContents, err error) {
	t, err := getByte(buf)
	if err != nil {
		return nil, err
	}

	switch t {
	case tagOpEndorsement:
		var op OpEndorsement
		if op.Level, err = getInt32(buf); err != nil {
			return nil, err
		}
		return &op, nil

	case tagOpEndorsementWithSlot:
		var op OpEndorsementWithSlot
		ln, err := getUint32(buf)
		if err != nil {
			return nil, err
		}
		tmpBuf, err := getBytes(buf, int(ln))
		if err != nil {
			return nil, err
		}
		e, err := parseInlinedEndorsement(&tmpBuf)
		if err != nil {
			return nil, err
		}
		op.InlinedEndorsement = *e
		if op.Slot, err = getUint16(buf); err != nil {
			return nil, err
		}

	case tagOpSeedNonceRevelation:
		var op OpSeedNonceRevelation
		if op.Level, err = getInt32(buf); err != nil {
			return nil, err
		}
		if op.Nonce, err = getBytes(buf, 32); err != nil {
			return nil, err
		}
		return &op, nil

	case tagOpDoubleEndorsementEvidence:
		var ee [2]*InlinedEndorsement
		for i := range ee {
			ln, err := getUint32(buf)
			if err != nil {
				return nil, err
			}
			tmpBuf, err := getBytes(buf, int(ln))
			if err != nil {
				return nil, err
			}
			op, err := parseInlinedEndorsement(&tmpBuf)
			if err != nil {
				return nil, err
			}
			ee[i] = op
		}
		return &OpDoubleEndorsementEvidence{
			Op1: ee[0],
			Op2: ee[1],
		}, nil

	case tagOpDoubleBakingEvidence:
		var op OpDoubleBakingEvidence
		ln, err := getUint32(buf)
		if err != nil {
			return nil, err
		}
		bhbuf, err := getBytes(buf, int(ln))
		if err != nil {
			return nil, err
		}
		if op.BlockHeader1, err = parseBlockHeader(&bhbuf, true); err != nil {
			return nil, err
		}
		if ln, err = getUint32(buf); err != nil {
			return nil, err
		}
		if bhbuf, err = getBytes(buf, int(ln)); err != nil {
			return nil, err
		}
		if op.BlockHeader2, err = parseBlockHeader(&bhbuf, true); err != nil {
			return nil, err
		}
		return &op, nil

	case tagOpActivateAccount:
		var op OpActivateAccount
		pkh, err := getBytes(buf, 20)
		if err != nil {
			return nil, err
		}
		op.PublicKeyHash = encodeBase58(pED25519PublicKeyHash, pkh)
		if op.Secret, err = getBytes(buf, 20); err != nil {
			return nil, err
		}
		return &op, nil

	case tagOpProposals:
		var op OpProposals
		if op.Source, err = parsePublicKeyHash(buf); err != nil {
			return nil, err
		}
		if op.Period, err = getInt32(buf); err != nil {
			return nil, err
		}
		ln, err := getUint32(buf)
		if err != nil {
			return nil, err
		}
		pbuf, err := getBytes(buf, int(ln))
		if err != nil {
			return nil, err
		}
		for len(pbuf) != 0 {
			prop, err := getBytes(&pbuf, 32)
			if err != nil {
				return nil, err
			}
			op.Proposals = append(op.Proposals, encodeBase58(pProtocolHash, prop))
		}
		return &op, nil

	case tagOpBallot:
		var op OpBallot
		if op.Source, err = parsePublicKeyHash(buf); err != nil {
			return nil, err
		}
		if op.Period, err = getInt32(buf); err != nil {
			return nil, err
		}
		prop, err := getBytes(buf, 32)
		if err != nil {
			return nil, err
		}
		op.Proposal = encodeBase58(pProtocolHash, prop)
		ballot, err := getByte(buf)
		if err != nil {
			return nil, err
		}
		switch ballot {
		case ballotYay:
			op.Ballot = "yay"
		case ballotNay:
			op.Ballot = "nay"
		default:
			op.Ballot = "pass"
		}
		return &op, nil

	case tagOpReveal, tagOpTransaction, tagOpOrigination, tagOpDelegation:
		var txCommon Manager
		if txCommon.Source, err = parsePublicKeyHash(buf); err != nil {
			return nil, err
		}
		if txCommon.Fee, err = parseBigNum(buf); err != nil {
			return nil, err
		}
		if txCommon.Counter, err = parseBigNum(buf); err != nil {
			return nil, err
		}
		if txCommon.GasLimit, err = parseBigNum(buf); err != nil {
			return nil, err
		}
		if txCommon.StorageLimit, err = parseBigNum(buf); err != nil {
			return nil, err
		}

		switch t {
		case tagOpReveal:
			op := OpReveal{
				Manager: txCommon,
			}
			if op.PublicKey, err = parsePublicKey(buf); err != nil {
				return nil, err
			}
			return &op, nil

		case tagOpTransaction:
			op := OpTransaction{
				Manager: txCommon,
			}
			if op.Amount, err = parseBigNum(buf); err != nil {
				return nil, err
			}
			if op.Destination, err = parseContractID(buf); err != nil {
				return nil, err
			}
			flag, err := getBool(buf)
			if err != nil {
				return nil, err
			}
			if flag {
				op.Parameters = new(TxParameters)
				if op.Parameters.Entrypoint, err = parseEntrypoint(buf); err != nil {
					return nil, err
				}
				ln, err := getUint32(buf)
				if err != nil {
					return nil, err
				}
				if op.Parameters.Value, err = getBytes(buf, int(ln)); err != nil {
					return nil, err
				}

			}
			return &op, nil

		case tagOpOrigination:
			op := OpOrigination{
				Manager: txCommon,
			}
			if op.Balance, err = parseBigNum(buf); err != nil {
				return nil, err
			}
			flag, err := getBool(buf)
			if err != nil {
				return nil, err
			}
			if flag {
				if op.Delegate, err = parsePublicKeyHash(buf); err != nil {
					return nil, err
				}
			}
			op.Script = new(ScriptedContracts)
			ln, err := getUint32(buf)
			if err != nil {
				return nil, err
			}
			if op.Script.Code, err = getBytes(buf, int(ln)); err != nil {
				return nil, err
			}
			ln, err = getUint32(buf)
			if err != nil {
				return nil, err
			}
			if op.Script.Storage, err = getBytes(buf, int(ln)); err != nil {
				return nil, err
			}
			return &op, nil

		case tagOpDelegation:
			op := OpDelegation{
				Manager: txCommon,
			}
			flag, err := getBool(buf)
			if err != nil {
				return nil, err
			}
			if flag {
				if op.Delegate, err = parsePublicKeyHash(buf); err != nil {
					return nil, err
				}
			}
			return &op, nil
		}
	}

	return nil, fmt.Errorf("tezos: unknown or unimplemented operation tag: %d", t)
}

func parseInlinedEndorsement(buf *[]byte) (op *InlinedEndorsement, err error) {
	branch, e, err := parseUnsignedEndorsement(buf)
	if err != nil {
		return
	}
	op = &InlinedEndorsement{
		Branch:        branch,
		OpEndorsement: *e,
	}
	sig, err := getBytes(buf, 64)
	if err != nil {
		return nil, err
	}
	op.Signature = encodeBase58(pGenericSignature, sig)
	return
}

const (
	tagPublicKeyHashED25519 = iota
	tagPublicKeyHashSECP256K1
	tagPublicKeyHashP256
)

func parsePublicKeyHash(buf *[]byte) (pkh string, err error) {
	t, err := getByte(buf)
	if err != nil {
		return "", err
	}

	var prefix tzPrefix
	switch t {
	case tagPublicKeyHashED25519:
		prefix = pED25519PublicKeyHash
	case tagPublicKeyHashSECP256K1:
		prefix = pSECP256K1PublicKeyHash
	case tagPublicKeyHashP256:
		prefix = pP256PublicKeyHash
	default:
		return "", fmt.Errorf("tezos: unknown public key hash tag: %d", t)
	}

	b, err := getBytes(buf, 20)
	if err != nil {
		return "", err
	}

	return encodeBase58(prefix, b), nil
}

const (
	tagPublicKeyED25519 = iota
	tagPublicKeySECP256K1
	tagPublicKeyP256
)

func parsePublicKey(buf *[]byte) (pkh string, err error) {
	t, err := getByte(buf)
	if err != nil {
		return "", err
	}

	var (
		prefix tzPrefix
		ln     int
	)
	switch t {
	case tagPublicKeyED25519:
		prefix = pED25519PublicKey
		ln = 32
	case tagPublicKeySECP256K1:
		prefix = pSECP256K1PublicKey
		ln = 33
	case tagPublicKeyP256:
		prefix = pP256PublicKey
		ln = 33
	default:
		return "", fmt.Errorf("tezos: unknown public key tag: %d", t)
	}

	b, err := getBytes(buf, ln)
	if err != nil {
		return "", err
	}
	return encodeBase58(prefix, b), nil
}

const (
	tagContractIDImplicit = iota
	tagContractIDOriginated
)

func parseContractID(buf *[]byte) (pkh string, err error) {
	t, err := getByte(buf)
	if err != nil {
		return "", err
	}

	switch t {
	case tagContractIDImplicit:
		pkh, err = parsePublicKeyHash(buf)
		if err != nil {
			return "", err
		}
		return pkh, nil

	case tagContractIDOriginated:
		b, err := getBytes(buf, 20)
		if err != nil {
			return "", err
		}
		pkh = encodeBase58(pContractHash, b)
		_, err = getByte(buf)
		return pkh, err
	}

	return "", fmt.Errorf("tezos: unknown contract id tag: %d", t)
}

func parseBigNum(buf *[]byte) (val *big.Int, err error) {
	val = new(big.Int)
	b := *buf
	msb := 0
	for msb < len(b) && b[msb]&0x80 != 0 {
		msb++
	}
	if msb == len(b) {
		return nil, ErrMsgUnexpectedEnd
	}
	for i := msb; i >= 0; i-- {
		var tmp big.Int
		tmp.SetInt64(int64(b[i] & 0x7f))
		val.Lsh(val, 7)
		val.Add(val, &tmp)
	}
	*buf = b[msb+1:]
	return val, nil
}

const (
	epDefault = iota
	epRoot
	epDo
	epSetDelegate
	epRemoveDelegate
)

const epNamed = 255

func parseEntrypoint(buf *[]byte) (e string, err error) {
	t, err := getByte(buf)
	if err != nil {
		return "", err
	}

	switch t {
	case epDefault:
		e = "default"
	case epRoot:
		e = "root"
	case epDo:
		e = "do"
	case epSetDelegate:
		e = "set_delegate"
	case epRemoveDelegate:
		e = "remove_delegate"
	case epNamed:
		ln, err := getByte(buf)
		if err != nil {
			return "", err
		}
		name, err := getBytes(buf, int(ln))
		if err != nil {
			return "", err
		}
		e = string(name)
	default:
		return "", fmt.Errorf("tezos: unknown entrypoint tag: %d", t)
	}
	return e, nil
}

func parseUnsignedOperation(buf *[]byte) (op *UnsignedOperation, err error) {
	blockHash, err := getBytes(buf, 32)
	if err != nil {
		return nil, err
	}

	branch := encodeBase58(pBlockHash, blockHash)

	list := make([]OperationContents, 0)
	for len(*buf) != 0 {
		op, err := parseOperation(buf)
		if err != nil {
			return nil, err
		}
		list = append(list, op)
	}

	return &UnsignedOperation{
		Branch:   branch,
		Contents: list,
	}, nil
}

func parseUnsignedEndorsement(buf *[]byte) (branch string, op *OpEndorsement, err error) {
	opBuf, err := getBytes(buf, 37)
	if err != nil {
		return
	}
	tmp, err := parseUnsignedOperation(&opBuf)
	if err != nil {
		return
	}
	if len(tmp.Contents) != 1 {
		// unlikely
		return "", nil, fmt.Errorf("tezos: single operation expected, got: %d", len(tmp.Contents))
	}
	op, ok := tmp.Contents[0].(*OpEndorsement)
	if !ok {
		return "", nil, fmt.Errorf("tezos: endorsement operation expected, got: %T", tmp)
	}
	return tmp.Branch, op, nil
}

// BlockHeader represents unsigned block header
type BlockHeader struct {
	Level                     int32
	Proto                     byte
	Predecessor               string
	Timestamp                 time.Time
	ValidationPass            byte
	OperationsHash            string
	Fitness                   [][]byte
	Context                   string
	Priority                  uint16
	ProofOfWorkNonce          []byte
	NonceHash                 []byte
	LiquidityBakingEscapeVote bool
	Signature                 string
}

// GetLevel returns block level
func (b *BlockHeader) GetLevel() int32 { return b.Level }

func parseBlockHeader(buf *[]byte, sig bool) (b *BlockHeader, err error) {
	b = new(BlockHeader)

	if b.Level, err = getInt32(buf); err != nil {
		return nil, err
	}
	if b.Proto, err = getByte(buf); err != nil {
		return nil, err
	}
	hash, err := getBytes(buf, 32)
	if err != nil {
		return nil, err
	}
	b.Predecessor = encodeBase58(pBlockHash, hash)
	ts, err := getInt64(buf)
	if err != nil {
		return nil, err
	}
	b.Timestamp = time.Unix(ts, 0).UTC()
	if b.ValidationPass, err = getByte(buf); err != nil {
		return nil, err
	}
	if hash, err = getBytes(buf, 32); err != nil {
		return nil, err
	}
	b.OperationsHash = encodeBase58(pOperationListListHash, hash)

	ln, err := getUint32(buf)
	if err != nil {
		return nil, err
	}
	fbuf, err := getBytes(buf, int(ln))
	if err != nil {
		return nil, err
	}
	for len(fbuf) != 0 {
		ln, err := getUint32(&fbuf)
		if err != nil {
			return nil, err
		}
		elem, err := getBytes(&fbuf, int(ln))
		if err != nil {
			return nil, err
		}
		b.Fitness = append(b.Fitness, elem)
	}
	if hash, err = getBytes(buf, 32); err != nil {
		return nil, err
	}
	b.Context = encodeBase58(pContextHash, hash)
	if b.Priority, err = getUint16(buf); err != nil {
		return nil, err
	}
	if b.ProofOfWorkNonce, err = getBytes(buf, 8); err != nil {
		return nil, err
	}
	flag, err := getBool(buf)
	if err != nil {
		return nil, err
	}
	if flag {
		if b.NonceHash, err = getBytes(buf, 32); err != nil {
			return nil, err
		}
	}
	b.LiquidityBakingEscapeVote, err = getBool(buf)
	if err != nil {
		return nil, err
	}
	if sig {
		s, err := getBytes(buf, 64)
		if err != nil {
			return nil, err
		}
		b.Signature = encodeBase58(pGenericSignature, s)
	}

	return b, nil
}

// MessageWithLevel is implemented by UnsignedBlockHeader and UnsignedEndorsement. Useful for high water marking.
type MessageWithLevel interface {
	UnsignedMessage
	GetLevel() int32
}

// MessageWithChainID is implemented by UnsignedBlockHeader and UnsignedEndorsement. Useful for high water marking.
type MessageWithChainID interface {
	UnsignedMessage
	GetChainID() string
}

// MessageWithLevelAndChainID is implemented by UnsignedBlockHeader and UnsignedEndorsement. Useful for high water marking.
type MessageWithLevelAndChainID interface {
	MessageWithLevel
	MessageWithChainID
}

type MessageWithRound interface {
	GetRound() int32
}

// UnsignedBlockHeader represents unsigned block header
type UnsignedBlockHeader struct {
	ChainID string
	BlockHeader
}

// MessageKind returns unsigned message kind name i.e. "block"
func (u *UnsignedBlockHeader) MessageKind() string { return "block" }

// GetChainID returns chain ID
func (u *UnsignedBlockHeader) GetChainID() string { return u.ChainID }

// UnsignedEndorsement represents unsigned endorsement
type UnsignedEndorsement struct {
	ChainID string
	Branch  string
	OpEndorsement
}

// MessageKind returns unsigned message kind name i.e. "endorsement"
func (u *UnsignedEndorsement) MessageKind() string { return "endorsement" }

// GetLevel returns block level
func (u *UnsignedEndorsement) GetLevel() int32 { return u.Level }

// GetChainID returns chain ID
func (u *UnsignedEndorsement) GetChainID() string { return u.ChainID }

const (
	magicBlockHeader              = 0x01
	magicEndorsement              = 0x02
	magicGenericOperation         = 0x03
	magicTenderbakeBlock          = 0x11
	magicTenderbakeEndorsement    = 0x12
	magicTenderbakePreendorsement = 0x13
)

func parseUnsignedMessage(buf *[]byte) (u UnsignedMessage, err error) {
	t, err := getByte(buf)
	if err != nil {
		return nil, err
	}

	switch t {
	case magicBlockHeader, magicEndorsement:
		b, err := getBytes(buf, 4)
		if err != nil {
			return nil, err
		}
		chainID := encodeBase58(pChainID, b)
		switch t {
		case magicBlockHeader:
			bh, err := parseBlockHeader(buf, false)
			if err != nil {
				return nil, err
			}
			return &UnsignedBlockHeader{
				ChainID:     chainID,
				BlockHeader: *bh,
			}, nil

		case magicEndorsement:
			branch, op, err := parseUnsignedEndorsement(buf)
			if err != nil {
				return nil, err
			}
			return &UnsignedEndorsement{
				ChainID:       chainID,
				Branch:        branch,
				OpEndorsement: *op,
			}, nil
		}

	case magicTenderbakeBlock:
	case magicTenderbakeEndorsement:
	case magicTenderbakePreendorsement:

	case magicGenericOperation:
		return parseUnsignedOperation(buf)
	}
	return nil, fmt.Errorf("tezos: unknown watermark tag: %d", t)
}

// ParseUnsignedMessage returns parsed sign request
func ParseUnsignedMessage(data []byte) (u UnsignedMessage, err error) {
	var buf = data
	return parseUnsignedMessage(&buf)
}

var (
	_ MessageWithLevelAndChainID = &UnsignedBlockHeader{}
	_ MessageWithLevelAndChainID = &UnsignedEndorsement{}
)
