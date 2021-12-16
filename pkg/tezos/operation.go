package tezos

import (
	"fmt"
	"math/big"
)

// Operation is implemented by all operations
type Operation interface {
	OperationKind() string
}

const (
	tagEndorsement                  = 0
	tagSeedNonceRevelation          = 1
	tagDoubleEndorsementEvidence    = 2
	tagDoubleBakingEvidence         = 3
	tagActivateAccount              = 4
	tagProposals                    = 5
	tagBallot                       = 6
	tagDoublePreendorsementEvidence = 7
	tagEndorsementWithSlot          = 10
	tagPreendorsement               = 20
	tagTenderbakeEndorsement        = 21
	tagReveal                       = 107
	tagTransaction                  = 108
	tagOrigination                  = 109
	tagDelegation                   = 110
	tagRegisterGlobalConstant       = 111
	tagSetDepositsLimit             = 112
	tagTxRollupOrigination          = 150
)

type OpEndorsement interface {
	Operation
	GetLevel() int32
	OpEndorsement()
}

// OpEmmyEndorsement represents "endorsement" operation
type OpEmmyEndorsement struct {
	Level int32
}

// GetLevel returns block level
func (o *OpEmmyEndorsement) GetLevel() int32 { return o.Level }

// OperationKind returns operation name i.e. "endorsement"
func (o *OpEmmyEndorsement) OperationKind() string { return "endorsement" }

func (*OpEmmyEndorsement) OpEndorsement() {}

// OpTenderbakeEndorsement represents "endorsement" operation
type OpTenderbakeEndorsement struct {
	Slot             *uint16
	Level            int32
	Round            int32
	BlockPayloadHash []byte
}

// GetLevel returns block level
func (o *OpTenderbakeEndorsement) GetLevel() int32 { return o.Level }

// OperationKind returns operation name i.e. "endorsement"
func (o *OpTenderbakeEndorsement) OperationKind() string { return "endorsement" }

func (*OpTenderbakeEndorsement) OpEndorsement() {}

// GetRound returns tenderbake round
func (o *OpTenderbakeEndorsement) GetRound() int32 { return o.Round }

// OpPreendorsement represents "preendorsement" operation
type OpPreendorsement OpTenderbakeEndorsement

// GetLevel returns block level
func (o *OpPreendorsement) GetLevel() int32 { return o.Level }

// OperationKind returns operation name i.e. "preendorsement"
func (o *OpPreendorsement) OperationKind() string { return "preendorsement" }

// GetRound returns tenderbake round
func (o *OpPreendorsement) GetRound() int32 { return o.Round }

// OpEndorsementWithSlot represents "endorsement" operation
type OpEndorsementWithSlot struct {
	InlinedEndorsement
	Slot uint16
}

// OperationKind returns operation name i.e. "endorsement_with_slot"
func (o *OpEndorsementWithSlot) OperationKind() string { return "endorsement" }

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
	OpEndorsement // either Emmy or Tenderbake
	Branch        string
	Signature     string
}

// InlinedPreendorsement represents inlined preendorsement operation with signature
type InlinedPreendorsement struct {
	OpPreendorsement
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

// OpDoublePreendorsementEvidence represents "double_preendorsement_evidence" operation
type OpDoublePreendorsementEvidence struct {
	Op1 *InlinedPreendorsement
	Op2 *InlinedPreendorsement
}

// OperationKind returns operation name i.e. "double_preendorsement_evidence"
func (o *OpDoublePreendorsementEvidence) OperationKind() string {
	return "double_preendorsement_evidence"
}

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

const (
	ballotYay = iota
	ballotNay
	ballotPass
)

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

// OpRegisterGlobalConstant represents "register_global_constant" operation
type OpRegisterGlobalConstant struct {
	Manager
	Value []byte
}

// OperationKind returns operation name i.e. "register_global_constant"
func (o *OpRegisterGlobalConstant) OperationKind() string { return "register_global_constant" }

type OpSetDepositsLimit struct {
	Manager
	Limit *big.Int
}

// OperationKind returns operation name i.e. "set_deposits_limit"
func (o *OpSetDepositsLimit) OperationKind() string { return "set_deposits_limit" }

type OpTxRollupOrigination Manager

// OperationKind returns operation name i.e. "tx_rollup_origination"
func (o *OpTxRollupOrigination) OperationKind() string { return "tx_rollup_origination" }

func parseOperation(buf *[]byte) (op Operation, err error) {
	t, err := getByte(buf)
	if err != nil {
		return nil, err
	}

	switch t {
	case tagEndorsement:
		var op OpEmmyEndorsement
		if op.Level, err = getInt32(buf); err != nil {
			return nil, err
		}
		return &op, nil

	case tagTenderbakeEndorsement, tagPreendorsement:
		var op OpTenderbakeEndorsement
		if s, err := getUint16(buf); err != nil {
			return nil, err
		} else {
			op.Slot = &s
		}
		if op.Level, err = getInt32(buf); err != nil {
			return nil, err
		}
		if op.Round, err = getInt32(buf); err != nil {
			return nil, err
		}
		if op.BlockPayloadHash, err = getBytes(buf, 32); err != nil {
			return nil, err
		}
		if t == tagPreendorsement {
			return (*OpPreendorsement)(&op), nil
		}
		return &op, nil

	case tagEndorsementWithSlot:
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

	case tagSeedNonceRevelation:
		var op OpSeedNonceRevelation
		if op.Level, err = getInt32(buf); err != nil {
			return nil, err
		}
		if op.Nonce, err = getBytes(buf, 32); err != nil {
			return nil, err
		}
		return &op, nil

	case tagDoubleEndorsementEvidence:
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

	case tagDoublePreendorsementEvidence:
		var ee [2]*InlinedPreendorsement
		for i := range ee {
			ln, err := getUint32(buf)
			if err != nil {
				return nil, err
			}
			tmpBuf, err := getBytes(buf, int(ln))
			if err != nil {
				return nil, err
			}
			op, err := parseInlinedPreendorsement(&tmpBuf)
			if err != nil {
				return nil, err
			}
			ee[i] = op
		}
		return &OpDoublePreendorsementEvidence{
			Op1: ee[0],
			Op2: ee[1],
		}, nil

	case tagDoubleBakingEvidence:
		var op OpDoubleBakingEvidence
		ln, err := getUint32(buf)
		if err != nil {
			return nil, err
		}
		bhbuf, err := getBytes(buf, int(ln))
		if err != nil {
			return nil, err
		}
		if op.BlockHeader1, err = parseBlockHeader(&bhbuf); err != nil {
			return nil, err
		}
		if ln, err = getUint32(buf); err != nil {
			return nil, err
		}
		if bhbuf, err = getBytes(buf, int(ln)); err != nil {
			return nil, err
		}
		if op.BlockHeader2, err = parseBlockHeader(&bhbuf); err != nil {
			return nil, err
		}
		return &op, nil

	case tagActivateAccount:
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

	case tagProposals:
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

	case tagBallot:
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

	case tagReveal, tagTransaction, tagOrigination, tagDelegation,
		tagRegisterGlobalConstant, tagSetDepositsLimit, tagTxRollupOrigination:
		var common Manager
		if common.Source, err = parsePublicKeyHash(buf); err != nil {
			return nil, err
		}
		if common.Fee, err = parseBigNum(buf); err != nil {
			return nil, err
		}
		if common.Counter, err = parseBigNum(buf); err != nil {
			return nil, err
		}
		if common.GasLimit, err = parseBigNum(buf); err != nil {
			return nil, err
		}
		if common.StorageLimit, err = parseBigNum(buf); err != nil {
			return nil, err
		}

		switch t {
		case tagReveal:
			op := OpReveal{
				Manager: common,
			}
			if op.PublicKey, err = parsePublicKey(buf); err != nil {
				return nil, err
			}
			return &op, nil

		case tagTransaction:
			op := OpTransaction{
				Manager: common,
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

		case tagOrigination:
			op := OpOrigination{
				Manager: common,
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

		case tagDelegation:
			op := OpDelegation{
				Manager: common,
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

		case tagRegisterGlobalConstant:
			op := OpRegisterGlobalConstant{
				Manager: common,
			}
			ln, err := getUint32(buf)
			if err != nil {
				return nil, err
			}
			if op.Value, err = getBytes(buf, int(ln)); err != nil {
				return nil, err
			}
			return &op, nil

		case tagSetDepositsLimit:
			op := OpSetDepositsLimit{
				Manager: common,
			}
			flag, err := getBool(buf)
			if err != nil {
				return nil, err
			}
			if flag {
				if op.Limit, err = parseBigNum(buf); err != nil {
					return nil, err
				}
			}
			return &op, nil

		case tagTxRollupOrigination:
			return (*OpTxRollupOrigination)(&common), nil
		}
	}

	return nil, fmt.Errorf("tezos: unknown or unimplemented operation tag: %d", t)
}

func parseInlinedEndorsement(buf *[]byte) (*InlinedEndorsement, error) {
	blockHash, err := getBytes(buf, 32)
	if err != nil {
		return nil, err
	}
	op, err := parseOperation(buf)
	if err != nil {
		return nil, err
	}
	e, ok := op.(OpEndorsement)
	if !ok {
		return nil, fmt.Errorf("tezos: endorsement operation expected, got: %T", op)
	}
	return &InlinedEndorsement{
		OpEndorsement: e,
		Branch:        encodeBase58(pBlockHash, blockHash),
		Signature:     encodeBase58(pGenericSignature, *buf),
	}, nil
}

func parseInlinedPreendorsement(buf *[]byte) (*InlinedPreendorsement, error) {
	blockHash, err := getBytes(buf, 32)
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
	return &InlinedPreendorsement{
		OpPreendorsement: *e,
		Branch:           encodeBase58(pBlockHash, blockHash),
		Signature:        encodeBase58(pGenericSignature, *buf),
	}, nil
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
