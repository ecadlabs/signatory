package tezos

import (
	"fmt"
	"math/big"
	"time"
)

const (
	tagOpEndorsement = iota
	tagOpSeedNonceRevelation
	tagOpDoubleEndorsementEvidence
	tagOpDoubleBakingEvidence
	tagOpActivateAccount
	tagOpProposals
	tagOpBallot
	tagOpReveal
	tagOpTransaction
	tagOpOrigination
	tagOpDelegation
)

const (
	tagBabylon = 100
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

// OpSeedNonceRevelation represents "seed_nonce_revelation" operation
type OpSeedNonceRevelation struct {
	Level int32
	Nonce []byte
}

// GetLevel returns block level
func (o *OpSeedNonceRevelation) GetLevel() int32 { return o.Level }

// OperationKind returns operation name i.e. "seed_nonce_revelation"
func (o *OpSeedNonceRevelation) OperationKind() string { return "seed_nonce_revelation" }

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
	Balance     *big.Int
	Delegate    string
	ManagerData *ManagerData // pre Babylon
	Script      *ScriptedContracts
}

// ManagerData represents pre Babylon manager data
type ManagerData struct {
	ManagerPubKey string
	Spendable     bool
	Delegatable   bool
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

	case tagOpSeedNonceRevelation:
		var op OpSeedNonceRevelation
		if op.Level, err = getInt32(buf); err != nil {
			return nil, err
		}
		if op.Nonce, err = getBytes(buf, 32); err != nil {
			return nil, err
		}
		return &op, nil

	//case tagOperationDoubleEndorsementEvidence:
	//case tagOperationDoubleBakingEvidence:

	case tagOpActivateAccount:
		var op OpActivateAccount
		pkh, err := getBytes(buf, 20)
		if err != nil {
			return nil, err
		}
		if op.PublicKeyHash, err = encodeBase58(pED25519PublicKeyHash, pkh); err != nil {
			return nil, err
		}
		if op.Secret, err = getBytes(buf, 20); err != nil {
			return nil, err
		}
		return &op, nil

	// case tagOpProposals:

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
		if op.Proposal, err = encodeBase58(pProtocolHash, prop); err != nil {
			return nil, err
		}
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

	case tagOpReveal, tagOpTransaction, tagOpOrigination, tagOpDelegation,
		tagOpReveal + tagBabylon, tagOpTransaction + tagBabylon, tagOpOrigination + tagBabylon, tagOpDelegation + tagBabylon:
		var txCommon Manager
		if t >= tagBabylon {
			if txCommon.Source, err = parsePublicKeyHash(buf); err != nil {
				return nil, err
			}
		} else if txCommon.Source, err = parseContractID(buf); err != nil {
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
		case tagOpReveal, tagOpReveal + tagBabylon:
			op := OpReveal{
				Manager: txCommon,
			}
			if op.PublicKey, err = parsePublicKey(buf); err != nil {
				return nil, err
			}
			return &op, nil

		case tagOpTransaction, tagOpTransaction + tagBabylon:
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
				if t >= tagBabylon {
					if op.Parameters.Entrypoint, err = parseEntrypoint(buf); err != nil {
						return nil, err
					}
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

		case tagOpOrigination, tagOpOrigination + tagBabylon:
			op := OpOrigination{
				Manager: txCommon,
			}
			if t < tagBabylon {
				op.ManagerData = new(ManagerData)
				if op.ManagerData.ManagerPubKey, err = parsePublicKeyHash(buf); err != nil {
					return nil, err
				}
			}
			if op.Balance, err = parseBigNum(buf); err != nil {
				return nil, err
			}
			if t < tagBabylon {
				if op.ManagerData.Spendable, err = getBool(buf); err != nil {
					return nil, err
				}
				if op.ManagerData.Delegatable, err = getBool(buf); err != nil {
					return nil, err
				}
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
			if t < tagBabylon {
				if flag, err = getBool(buf); err != nil {
					return nil, err
				}
			} else {
				flag = true
			}
			if flag {
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
			}
			return &op, nil

		case tagOpDelegation, tagOpDelegation + tagBabylon:
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

	pkh, err = encodeBase58(prefix, b)
	if err != nil {
		return "", err
	}

	return pkh, nil
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

	pkh, err = encodeBase58(prefix, b)
	if err != nil {
		return "", err
	}

	return pkh, nil
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
		pkh, err = encodeBase58(pContractHash, b)
		if err != nil {
			return "", err
		}
		_, err = getByte(buf)
		if err != nil {
			return "", err
		}
		return pkh, nil
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

	branch, err := encodeBase58(pBlockHash, blockHash)
	if err != nil {
		return nil, err
	}

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

// BlockHeader represents unsigned block header
type BlockHeader struct {
	Level            int32
	Proto            byte
	Predecessor      string
	Timestamp        time.Time
	ValidationPass   byte
	OperationsHash   string
	Fitness          [][]byte
	Context          string
	Priority         uint16
	NonceHash        []byte
	ProofOfWorkNonce []byte
}

// GetLevel returns block level
func (b *BlockHeader) GetLevel() int32 { return b.Level }

func parseBlockHeader(buf *[]byte) (b *BlockHeader, err error) {
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
	if b.Predecessor, err = encodeBase58(pBlockHash, hash); err != nil {
		return nil, err
	}
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
	if b.OperationsHash, err = encodeBase58(pOperationListListHash, hash); err != nil {
		return nil, err
	}

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
	if b.Context, err = encodeBase58(pContextHash, hash); err != nil {
		return nil, err
	}
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
	return b, nil
}

// MessageWithLevel is implemented by UnsignedBlockHeader and UnsignedEndorsement. Useful for high water marking.
type MessageWithLevel interface {
	GetLevel() int32
}

// MessageWithChainID is implemented by UnsignedBlockHeader and UnsignedEndorsement. Useful for high water marking.
type MessageWithChainID interface {
	GetChainID() string
}

// MessageWithLevelAndChainID is implemented by UnsignedBlockHeader and UnsignedEndorsement. Useful for high water marking.
type MessageWithLevelAndChainID interface {
	MessageWithLevel
	MessageWithChainID
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
	OpEndorsement
}

// MessageKind returns unsigned message kind name i.e. "endorsement"
func (u *UnsignedEndorsement) MessageKind() string { return "endorsement" }

// GetLevel returns block level
func (u *UnsignedEndorsement) GetLevel() int32 { return u.Level }

// GetChainID returns chain ID
func (u *UnsignedEndorsement) GetChainID() string { return u.ChainID }

// Watermark prefixes
// see https://gitlab.com/tezos/tezos/blob/master/src/lib_crypto/signature.ml#L669
const (
	wmBlockHeader      = 1
	wmEndorsement      = 2
	wmGenericOperation = 3
)

// ParseUnsignedMessage returns parsed sign request
func ParseUnsignedMessage(data []byte) (u UnsignedMessage, err error) {
	buf := data
	t, err := getByte(&buf)
	if err != nil {
		return nil, err
	}

	switch t {
	case wmBlockHeader, wmEndorsement:
		b, err := getBytes(&buf, 4)
		if err != nil {
			return nil, err
		}
		chainID, err := encodeBase58(pChainID, b)
		if err != nil {
			return nil, err
		}
		switch t {
		case wmBlockHeader:
			bh, err := parseBlockHeader(&buf)
			if err != nil {
				return nil, err
			}
			return &UnsignedBlockHeader{
				ChainID:     chainID,
				BlockHeader: *bh,
			}, nil

		case wmEndorsement:
			// level is the last 4 bytes
			l := buf[len(buf)-4:]
			level, err := getInt32(&l)
			if err != nil {
				return nil, err
			}
			return &UnsignedEndorsement{
				ChainID: chainID,
				OpEndorsement: OpEndorsement{
					Level: level,
				},
			}, nil
		}
	case wmGenericOperation:
		return parseUnsignedOperation(&buf)
	}
	return nil, fmt.Errorf("tezos: unknown watermark tag: %d", t)
}

var (
	_ MessageWithLevelAndChainID = &UnsignedBlockHeader{}
	_ MessageWithLevelAndChainID = &UnsignedEndorsement{}
)
