package tezos

import (
	"fmt"
	"math/big"
	"sort"

	"github.com/ecadlabs/signatory/pkg/tezos/utils"
)

// Operation is implemented by all operations
type Operation interface {
	OperationKind() string
}

const (
	tagEmmyEndorsement              = 0
	tagSeedNonceRevelation          = 1
	tagDoubleEndorsementEvidence    = 2
	tagDoubleBakingEvidence         = 3
	tagActivateAccount              = 4
	tagProposals                    = 5
	tagBallot                       = 6
	tagDoublePreendorsementEvidence = 7
	tagVdfRevelation                = 8
	tagDrainDelegate                = 9
	tagEndorsementWithSlot          = 10
	tagFailingNoop                  = 17
	tagPreendorsement               = 20
	tagTenderbakeEndorsement        = 21
	tagReveal                       = 107
	tagTransaction                  = 108
	tagOrigination                  = 109
	tagDelegation                   = 110
	tagRegisterGlobalConstant       = 111
	tagSetDepositsLimit             = 112
	tagIncreasePaidStorageLimit     = 113
	tagUpdateConsensusKey           = 114
	tagTxRollupOrigination          = 150
	tagTxRollupSubmitBatch          = 151
	tagTxRollupCommit               = 152
	tagTxRollupReturnBond           = 153
	tagTxRollupFinalizeCommitment   = 154
	tagTxRollupRemoveCommitment     = 155
	tagTxRollupRejection            = 156
	tagTxRollupDispatchTickets      = 157
	tagTransferTicket               = 158
	tagScRollupOriginate            = 200
	tagScRollupAddMessages          = 201
	tagScRollupCement               = 202
	tagScRollupPublish              = 203
)

var opKinds = map[int]string{
	tagEmmyEndorsement:              "endorsement",
	tagSeedNonceRevelation:          "seed_nonce_revelation",
	tagDoubleEndorsementEvidence:    "double_endorsement_evidence",
	tagDoubleBakingEvidence:         "double_baking_evidence",
	tagActivateAccount:              "activate_account",
	tagProposals:                    "proposals",
	tagBallot:                       "ballot",
	tagDoublePreendorsementEvidence: "double_preendorsement_evidence",
	tagVdfRevelation:                "vdf_revelation",
	tagDrainDelegate:                "drain_delegate",
	tagEndorsementWithSlot:          "endorsement_with_slot",
	tagFailingNoop:                  "failing_noop",
	tagPreendorsement:               "preendorsement",
	tagTenderbakeEndorsement:        "endorsement",
	tagReveal:                       "reveal",
	tagTransaction:                  "transaction",
	tagOrigination:                  "origination",
	tagDelegation:                   "delegation",
	tagRegisterGlobalConstant:       "register_global_constant",
	tagSetDepositsLimit:             "set_deposits_limit",
	tagIncreasePaidStorageLimit:     "increase_paid_storage",
	tagUpdateConsensusKey:           "update_consensus_key",
	tagTxRollupOrigination:          "tx_rollup_origination",
	tagTxRollupSubmitBatch:          "tx_rollup_submit_batch",
	tagTxRollupCommit:               "tx_rollup_commit",
	tagTxRollupReturnBond:           "tx_rollup_return_bond",
	tagTxRollupFinalizeCommitment:   "tx_rollup_finalize_commitment",
	tagTxRollupRemoveCommitment:     "tx_rollup_remove_commitment",
	tagTxRollupRejection:            "tx_rollup_rejection",
	tagTxRollupDispatchTickets:      "tx_rollup_dispatch_tickets",
	tagTransferTicket:               "transfer_ticket",
	tagScRollupOriginate:            "sc_rollup_originate",
	tagScRollupAddMessages:          "sc_rollup_add_messages",
	tagScRollupCement:               "sc_rollup_cement",
	tagScRollupPublish:              "sc_rollup_publish",
}

type Endorsement interface {
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
	Slot             uint16
	Level            int32
	Round            int32
	BlockPayloadHash string
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

func (*OpPreendorsement) OpEndorsement() {}

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
	Endorsement // either Emmy or Tenderbake
	Branch      string
	Signature   string
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
	BlockHeader1 *ShellBlockHeader
	BlockHeader2 *ShellBlockHeader
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

type Rollup struct {
	Manager
	Rollup string
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

// ScriptedContract contains contract data
type ScriptedContract struct {
	Code    []byte
	Storage []byte
}

// OpOrigination represents "origination" operation
type OpOrigination struct {
	Manager
	Balance  *big.Int
	Delegate string
	Script   *ScriptedContract
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

type OpTxRollupSubmitBatch struct {
	Rollup
	Content   []byte
	BurnLimit *big.Int
}

func (o *OpTxRollupSubmitBatch) OperationKind() string { return "tx_rollup_submit_batch" }

type OpTxRollupCommit struct {
	Rollup
	Level           int32
	Messages        []string
	Predecessor     string
	InboxMerkleRoot string
}

func (o *OpTxRollupCommit) OperationKind() string { return "tx_rollup_commit" }

type OpTxRollupReturnBond Rollup

func (o *OpTxRollupReturnBond) OperationKind() string { return "tx_rollup_return_bond" }

type OpTxRollupFinalizeCommitment Rollup

func (o *OpTxRollupFinalizeCommitment) OperationKind() string { return "tx_rollup_finalize_commitment" }

type OpTxRollupRemoveCommitment Rollup

func (o *OpTxRollupRemoveCommitment) OperationKind() string { return "tx_rollup_remove_commitment" }

type RollupMessage interface {
	RollupMessage()
}

const (
	tagMessageBatch = iota
	tagMessageDeposit
)

type RollupMessageBatch []byte

func (RollupMessageBatch) RollupMessage() {}

type RollupMessageDeposit struct {
	Sender      string
	Destination string
	TicketHash  string
	Amount      int64
}

func (*RollupMessageDeposit) RollupMessage() {}

type MessageResult struct {
	ContextHash      string
	WithdrawListHash string
}

type OpTxRollupRejection struct {
	Rollup
	Level                     int32
	Message                   RollupMessage
	MessagePosition           *big.Int
	MessagePath               []string
	MessageResultHash         string
	MessageResultPath         []string
	PreviousMessageResult     MessageResult
	PreviousMessageResultPath []string
	// not well documented
	// Proof                     Proof
}

func (o *OpTxRollupRejection) OperationKind() string { return "tx_rollup_rejection" }

type OpTxRollupDispatchTickets struct {
	Rollup
	Level             int32
	ContextHash       string
	MessageIndex      int32
	MessageResultPath []string
	TicketsInfo       []TicketInfo
}

func (o *OpTxRollupDispatchTickets) OperationKind() string { return "tx_rollup_dispatch_tickets" }

type TicketInfo struct {
	Contents []byte // expr
	Ty       []byte // expr
	Ticketer string
	Amount   int64
	Claimer  string
}

type OpTransferTicket struct {
	Manager
	TicketContents []byte // expr
	TicketTy       []byte // expr
	TicketTicketer string
	TicketAmount   *big.Int
	Destination    string
	Entrypoint     string
}

func (o *OpTransferTicket) OperationKind() string { return "transfer_ticket" }

type OpScRollupOriginate struct {
	Manager
	Kind       uint16
	BootSector string
}

func (o *OpScRollupOriginate) OperationKind() string { return "sc_rollup_originate" }

type OpScRollupAddMessages struct {
	Manager
	Rollup  string
	Message []string
}

func (o *OpScRollupAddMessages) OperationKind() string { return "sc_rollup_add_messages" }

type OpScRollupCement struct {
	Manager
	Rollup     string
	Commitment string
}

func (o *OpScRollupCement) OperationKind() string { return "sc_rollup_cement" }

type OpScRollupPublish struct {
	Manager
	Rollup     string
	Commitment Commitment
}

type OpIncreasePaidStorage struct {
	Manager
	Amount      *big.Int
	Destination string
}

func (o *OpIncreasePaidStorage) OperationKind() string { return "increase_paid_storage" }

type OpUpdateConsensusKey struct {
	Manager
	ConsesusKey string
}

func (o *OpUpdateConsensusKey) OperationKind() string { return "update_consensus_key" }

type OpDrainDelegate struct {
	Manager
	ConsesusKey string
	Delegate    string
	Destination string
}

func (o *OpDrainDelegate) OperationKind() string { return "drain_delegate" }

type Commitment struct {
	CompressedState  string
	InboxLevel       int32
	Predecessor      string
	NumberOfMessages int32
	NumberOfTicks    int32 // 🕷
}

func (o *OpScRollupPublish) OperationKind() string { return "sc_rollup_publish" }

type OpFailingNoop []byte

func (o OpFailingNoop) OperationKind() string { return "failing_noop" }

type OpVdfRevelation []byte

func (o OpVdfRevelation) OperationKind() string { return "vdf_revelation" }

func parseOperation(buf *[]byte) (op Operation, err error) {
	t, err := utils.GetByte(buf)
	if err != nil {
		return nil, fmt.Errorf("operation: %w", err)
	}

	switch t {
	case tagVdfRevelation:
		var op OpVdfRevelation
		if op, err = utils.GetBytes(buf, 200); err != nil {
			return nil, fmt.Errorf("%s: %w", opKinds[int(t)], err)
		}
		return &op, nil

	case tagDrainDelegate:
		var op OpDrainDelegate
		if op.ConsesusKey, err = parsePublicKeyHash(buf); err != nil {
			return nil, fmt.Errorf("%s: %w", opKinds[int(t)], err)
		}
		if op.Delegate, err = parsePublicKeyHash(buf); err != nil {
			return nil, fmt.Errorf("%s: %w", opKinds[int(t)], err)
		}
		if op.Destination, err = parsePublicKeyHash(buf); err != nil {
			return nil, fmt.Errorf("%s: %w", opKinds[int(t)], err)
		}
		return &op, nil

	case tagEmmyEndorsement:
		var op OpEmmyEndorsement
		if op.Level, err = utils.GetInt32(buf); err != nil {
			return nil, fmt.Errorf("%s: %w", opKinds[int(t)], err)
		}
		return &op, nil

	case tagTenderbakeEndorsement, tagPreendorsement:
		var (
			op  OpTenderbakeEndorsement
			err error
		)
		if op.Slot, err = utils.GetUint16(buf); err != nil {
			return nil, fmt.Errorf("%s: %w", opKinds[int(t)], err)
		}
		if op.Level, err = utils.GetInt32(buf); err != nil {
			return nil, fmt.Errorf("%s: %w", opKinds[int(t)], err)
		}
		if op.Round, err = utils.GetInt32(buf); err != nil {
			return nil, fmt.Errorf("%s: %w", opKinds[int(t)], err)
		}
		hash, err := utils.GetBytes(buf, 32)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", opKinds[int(t)], err)
		}
		op.BlockPayloadHash = encodeBase58(pValueHash, hash)
		if t == tagPreendorsement {
			return (*OpPreendorsement)(&op), nil
		}
		return &op, nil

	case tagEndorsementWithSlot:
		var op OpEndorsementWithSlot
		ln, err := utils.GetUint32(buf)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", opKinds[int(t)], err)
		}
		tmpBuf, err := utils.GetBytes(buf, int(ln))
		if err != nil {
			return nil, fmt.Errorf("%s: %w", opKinds[int(t)], err)
		}
		e, err := parseInlinedEndorsement(&tmpBuf)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", opKinds[int(t)], err)
		}
		op.InlinedEndorsement = *e
		if op.Slot, err = utils.GetUint16(buf); err != nil {
			return nil, fmt.Errorf("%s: %w", opKinds[int(t)], err)
		}
		return &op, nil

	case tagFailingNoop:
		ln, err := utils.GetUint32(buf)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", opKinds[int(t)], err)
		}
		v, err := utils.GetBytes(buf, int(ln))
		if err != nil {
			return nil, fmt.Errorf("%s: %w", opKinds[int(t)], err)
		}
		return OpFailingNoop(v), nil

	case tagSeedNonceRevelation:
		var op OpSeedNonceRevelation
		if op.Level, err = utils.GetInt32(buf); err != nil {
			return nil, fmt.Errorf("%s: %w", opKinds[int(t)], err)
		}
		if op.Nonce, err = utils.GetBytes(buf, 32); err != nil {
			return nil, fmt.Errorf("%s: %w", opKinds[int(t)], err)
		}
		return &op, nil

	case tagDoubleEndorsementEvidence:
		var ee [2]*InlinedEndorsement
		for i := range ee {
			ln, err := utils.GetUint32(buf)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", opKinds[int(t)], err)
			}
			tmpBuf, err := utils.GetBytes(buf, int(ln))
			if err != nil {
				return nil, fmt.Errorf("%s: %w", opKinds[int(t)], err)
			}
			op, err := parseInlinedEndorsement(&tmpBuf)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", opKinds[int(t)], err)
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
			ln, err := utils.GetUint32(buf)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", opKinds[int(t)], err)
			}
			tmpBuf, err := utils.GetBytes(buf, int(ln))
			if err != nil {
				return nil, fmt.Errorf("%s: %w", opKinds[int(t)], err)
			}
			op, err := parseInlinedPreendorsement(&tmpBuf)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", opKinds[int(t)], err)
			}
			ee[i] = op
		}
		return &OpDoublePreendorsementEvidence{
			Op1: ee[0],
			Op2: ee[1],
		}, nil

	case tagDoubleBakingEvidence:
		var op OpDoubleBakingEvidence
		ln, err := utils.GetUint32(buf)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", opKinds[int(t)], err)
		}
		bhbuf, err := utils.GetBytes(buf, int(ln))
		if err != nil {
			return nil, fmt.Errorf("%s: %w", opKinds[int(t)], err)
		}
		if op.BlockHeader1, err = parseShellBlockHeader(&bhbuf); err != nil {
			return nil, fmt.Errorf("%s: %w", opKinds[int(t)], err)
		}
		if ln, err = utils.GetUint32(buf); err != nil {
			return nil, fmt.Errorf("%s: %w", opKinds[int(t)], err)
		}
		if bhbuf, err = utils.GetBytes(buf, int(ln)); err != nil {
			return nil, fmt.Errorf("%s: %w", opKinds[int(t)], err)
		}
		if op.BlockHeader2, err = parseShellBlockHeader(&bhbuf); err != nil {
			return nil, fmt.Errorf("%s: %w", opKinds[int(t)], err)
		}
		return &op, nil

	case tagActivateAccount:
		var op OpActivateAccount
		pkh, err := utils.GetBytes(buf, 20)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", opKinds[int(t)], err)
		}
		op.PublicKeyHash = encodeBase58(pED25519PublicKeyHash, pkh)
		if op.Secret, err = utils.GetBytes(buf, 20); err != nil {
			return nil, fmt.Errorf("%s: %w", opKinds[int(t)], err)
		}
		return &op, nil

	case tagProposals:
		var op OpProposals
		if op.Source, err = parsePublicKeyHash(buf); err != nil {
			return nil, fmt.Errorf("%s: %w", opKinds[int(t)], err)
		}
		if op.Period, err = utils.GetInt32(buf); err != nil {
			return nil, fmt.Errorf("%s: %w", opKinds[int(t)], err)
		}
		ln, err := utils.GetUint32(buf)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", opKinds[int(t)], err)
		}
		pbuf, err := utils.GetBytes(buf, int(ln))
		if err != nil {
			return nil, fmt.Errorf("%s: %w", opKinds[int(t)], err)
		}
		for len(pbuf) != 0 {
			prop, err := utils.GetBytes(&pbuf, 32)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", opKinds[int(t)], err)
			}
			op.Proposals = append(op.Proposals, encodeBase58(pProtocolHash, prop))
		}
		return &op, nil

	case tagBallot:
		var op OpBallot
		if op.Source, err = parsePublicKeyHash(buf); err != nil {
			return nil, fmt.Errorf("%s: %w", opKinds[int(t)], err)
		}
		if op.Period, err = utils.GetInt32(buf); err != nil {
			return nil, fmt.Errorf("%s: %w", opKinds[int(t)], err)
		}
		prop, err := utils.GetBytes(buf, 32)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", opKinds[int(t)], err)
		}
		op.Proposal = encodeBase58(pProtocolHash, prop)
		ballot, err := utils.GetByte(buf)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", opKinds[int(t)], err)
		}
		switch ballot {
		case ballotYay:
			op.Ballot = "yay"
		case ballotNay:
			op.Ballot = "nay"
		case ballotPass:
			op.Ballot = "pass"
		default:
			return nil, fmt.Errorf("invalid ballot: %d", ballot)
		}
		return &op, nil

	case tagReveal,
		tagTransaction,
		tagOrigination,
		tagDelegation,
		tagRegisterGlobalConstant,
		tagSetDepositsLimit,
		tagIncreasePaidStorageLimit,
		tagUpdateConsensusKey,
		tagTxRollupOrigination,
		tagTxRollupSubmitBatch,
		tagTxRollupCommit,
		tagTxRollupReturnBond,
		tagTxRollupFinalizeCommitment,
		tagTxRollupRemoveCommitment,
		tagTxRollupRejection,
		tagTxRollupDispatchTickets,
		tagTransferTicket,
		tagScRollupOriginate,
		tagScRollupAddMessages,
		tagScRollupCement,
		tagScRollupPublish:
		var common Manager
		if common.Source, err = parsePublicKeyHash(buf); err != nil {
			return nil, fmt.Errorf("%s: %w", opKinds[int(t)], err)
		}
		if common.Fee, err = parseBigUint(buf); err != nil {
			return nil, fmt.Errorf("%s: %w", opKinds[int(t)], err)
		}
		if common.Counter, err = parseBigUint(buf); err != nil {
			return nil, fmt.Errorf("%s: %w", opKinds[int(t)], err)
		}
		if common.GasLimit, err = parseBigUint(buf); err != nil {
			return nil, fmt.Errorf("%s: %w", opKinds[int(t)], err)
		}
		if common.StorageLimit, err = parseBigUint(buf); err != nil {
			return nil, fmt.Errorf("%s: %w", opKinds[int(t)], err)
		}

		switch t {
		case tagReveal:
			op := OpReveal{
				Manager: common,
			}
			if op.PublicKey, err = parsePublicKey(buf); err != nil {
				return nil, fmt.Errorf("%s: %w", opKinds[int(t)], err)
			}
			return &op, nil

		case tagTransaction:
			op := OpTransaction{
				Manager: common,
			}
			if op.Amount, err = parseBigUint(buf); err != nil {
				return nil, fmt.Errorf("%s: %w", opKinds[int(t)], err)
			}
			if op.Destination, err = parseDestination(buf); err != nil {
				return nil, fmt.Errorf("%s: %w", opKinds[int(t)], err)
			}
			flag, err := utils.GetBool(buf)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", opKinds[int(t)], err)
			}
			if flag {
				op.Parameters = new(TxParameters)
				if op.Parameters.Entrypoint, err = parseEntrypoint(buf); err != nil {
					return nil, fmt.Errorf("%s: %w", opKinds[int(t)], err)
				}
				ln, err := utils.GetUint32(buf)
				if err != nil {
					return nil, fmt.Errorf("%s: %w", opKinds[int(t)], err)
				}
				if op.Parameters.Value, err = utils.GetBytes(buf, int(ln)); err != nil {
					return nil, fmt.Errorf("%s: %w", opKinds[int(t)], err)
				}

			}
			return &op, nil

		case tagOrigination:
			op := OpOrigination{
				Manager: common,
			}
			if op.Balance, err = parseBigUint(buf); err != nil {
				return nil, fmt.Errorf("%s: %w", opKinds[int(t)], err)
			}
			flag, err := utils.GetBool(buf)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", opKinds[int(t)], err)
			}
			if flag {
				if op.Delegate, err = parsePublicKeyHash(buf); err != nil {
					return nil, fmt.Errorf("%s: %w", opKinds[int(t)], err)
				}
			}
			op.Script = new(ScriptedContract)
			ln, err := utils.GetUint32(buf)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", opKinds[int(t)], err)
			}
			if op.Script.Code, err = utils.GetBytes(buf, int(ln)); err != nil {
				return nil, fmt.Errorf("%s: %w", opKinds[int(t)], err)
			}
			ln, err = utils.GetUint32(buf)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", opKinds[int(t)], err)
			}
			if op.Script.Storage, err = utils.GetBytes(buf, int(ln)); err != nil {
				return nil, fmt.Errorf("%s: %w", opKinds[int(t)], err)
			}
			return &op, nil

		case tagDelegation:
			op := OpDelegation{
				Manager: common,
			}
			flag, err := utils.GetBool(buf)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", opKinds[int(t)], err)
			}
			if flag {
				if op.Delegate, err = parsePublicKeyHash(buf); err != nil {
					return nil, fmt.Errorf("%s: %w", opKinds[int(t)], err)
				}
			}
			return &op, nil

		case tagRegisterGlobalConstant:
			op := OpRegisterGlobalConstant{
				Manager: common,
			}
			ln, err := utils.GetUint32(buf)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", opKinds[int(t)], err)
			}
			if op.Value, err = utils.GetBytes(buf, int(ln)); err != nil {
				return nil, fmt.Errorf("%s: %w", opKinds[int(t)], err)
			}
			return &op, nil

		case tagSetDepositsLimit:
			op := OpSetDepositsLimit{
				Manager: common,
			}
			flag, err := utils.GetBool(buf)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", opKinds[int(t)], err)
			}
			if flag {
				if op.Limit, err = parseBigUint(buf); err != nil {
					return nil, fmt.Errorf("%s: %w", opKinds[int(t)], err)
				}
			}
			return &op, nil

		case tagIncreasePaidStorageLimit:
			op := OpIncreasePaidStorage{
				Manager: common,
			}
			op.Amount, err = parseBigInt(buf)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", opKinds[int(t)], err)
			}
			dest, err := parseDestination(buf)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", opKinds[int(t)], err)
			}
			op.Destination = string(dest)
			return &op, nil

		case tagUpdateConsensusKey:
			op := OpUpdateConsensusKey{
				Manager: common,
			}
			dest, err := parsePublicKey(buf)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", opKinds[int(t)], err)
			}
			op.ConsesusKey = string(dest)
			return &op, nil

		case tagTxRollupOrigination:
			return (*OpTxRollupOrigination)(&common), nil

		case tagTxRollupSubmitBatch,
			tagTxRollupCommit,
			tagTxRollupReturnBond,
			tagTxRollupFinalizeCommitment,
			tagTxRollupRemoveCommitment,
			tagTxRollupRejection,
			tagTxRollupDispatchTickets:

			rollup := Rollup{
				Manager: common,
			}
			if r, err := utils.GetBytes(buf, 20); err != nil {
				return nil, fmt.Errorf("%s: %w", opKinds[int(t)], err)
			} else {
				rollup.Rollup = encodeBase58(pRollupAddress, r)
			}

			switch t {
			case tagTxRollupSubmitBatch:
				op := OpTxRollupSubmitBatch{
					Rollup: rollup,
				}
				ln, err := utils.GetUint32(buf)
				if err != nil {
					return nil, fmt.Errorf("%s: %w", opKinds[int(t)], err)
				}
				if op.Content, err = utils.GetBytes(buf, int(ln)); err != nil {
					return nil, fmt.Errorf("%s: %w", opKinds[int(t)], err)
				}
				flag, err := utils.GetBool(buf)
				if err != nil {
					return nil, fmt.Errorf("%s: %w", opKinds[int(t)], err)
				}
				if flag {
					if op.BurnLimit, err = parseBigUint(buf); err != nil {
						return nil, fmt.Errorf("%s: %w", opKinds[int(t)], err)
					}
				}
				return &op, nil

			case tagTxRollupCommit:
				op := OpTxRollupCommit{
					Rollup: rollup,
				}
				if op.Level, err = utils.GetInt32(buf); err != nil {
					return nil, fmt.Errorf("%s: %w", opKinds[int(t)], err)
				}
				ln, err := utils.GetUint32(buf)
				if err != nil {
					return nil, fmt.Errorf("%s: %w", opKinds[int(t)], err)
				}
				if mbuf, err := utils.GetBytes(buf, int(ln)); err != nil {
					return nil, fmt.Errorf("%s: %w", opKinds[int(t)], err)
				} else {
					for len(mbuf) != 0 {
						msg, err := utils.GetBytes(&mbuf, 32)
						if err != nil {
							return nil, fmt.Errorf("%s: %w", opKinds[int(t)], err)
						}
						op.Messages = append(op.Messages, encodeBase58(pMessageResultHash, msg))
					}
				}
				tag, err := utils.GetByte(buf)
				if err != nil {
					return nil, fmt.Errorf("%s: %w", opKinds[int(t)], err)
				}
				switch tag {
				case 0:
				case 1:
					if p, err := utils.GetBytes(buf, 32); err != nil {
						return nil, fmt.Errorf("%s: %w", opKinds[int(t)], err)
					} else {
						op.Predecessor = encodeBase58(pCommitmentHash, p)
					}
				default:
					return nil, fmt.Errorf("%s: unexpected tag", opKinds[int(t)])
				}
				if r, err := utils.GetBytes(buf, 32); err != nil {
					return nil, fmt.Errorf("%s: %w", opKinds[int(t)], err)
				} else {
					op.InboxMerkleRoot = encodeBase58(pInboxHash, r)
				}
				return &op, nil

			case tagTxRollupReturnBond:
				return (*OpTxRollupReturnBond)(&rollup), nil

			case tagTxRollupFinalizeCommitment:
				return (*OpTxRollupFinalizeCommitment)(&rollup), nil

			case tagTxRollupRemoveCommitment:
				return (*OpTxRollupRemoveCommitment)(&rollup), nil

			case tagTxRollupRejection:
				op := OpTxRollupRejection{
					Rollup: rollup,
				}
				if op.Level, err = utils.GetInt32(buf); err != nil {
					return nil, fmt.Errorf("%s: %w", opKinds[int(t)], err)
				}
				tag, err := utils.GetByte(buf)
				if err != nil {
					return nil, fmt.Errorf("%s: %w", opKinds[int(t)], err)
				}
				switch tag {
				case tagMessageBatch:
					ln, err := utils.GetUint32(buf)
					if err != nil {
						return nil, fmt.Errorf("%s: %w", opKinds[int(t)], err)
					}
					if v, err := utils.GetBytes(buf, int(ln)); err != nil {
						return nil, fmt.Errorf("%s: %w", opKinds[int(t)], err)
					} else {
						op.Message = RollupMessageBatch(v)
					}

				case tagMessageDeposit:
					m := RollupMessageDeposit{}
					if m.Sender, err = parsePublicKeyHash(buf); err != nil {
						return nil, fmt.Errorf("%s: %w", opKinds[int(t)], err)
					}
					if v, err := utils.GetBytes(buf, 20); err != nil {
						return nil, fmt.Errorf("%s: %w", opKinds[int(t)], err)
					} else {
						op.Message = RollupMessageBatch(v)
					}
					if b, err := utils.GetBytes(buf, 20); err != nil {
						return nil, fmt.Errorf("%s: %w", opKinds[int(t)], err)
					} else {
						m.Destination = encodeBase58(pL2Address, b)
					}
					if b, err := utils.GetBytes(buf, 32); err != nil {
						return nil, fmt.Errorf("%s: %w", opKinds[int(t)], err)
					} else {
						m.TicketHash = encodeBase58(pScriptExpr, b)
					}
					if m.Amount, err = parseAmount(buf); err != nil {
						return nil, fmt.Errorf("%s: %w", opKinds[int(t)], err)
					}
					op.Message = &m
				}
				if op.MessagePosition, err = parseBigUint(buf); err != nil {
					return nil, fmt.Errorf("%s: %w", opKinds[int(t)], err)
				}
				ln, err := utils.GetUint32(buf)
				if err != nil {
					return nil, fmt.Errorf("%s: %w", opKinds[int(t)], err)
				}
				if pbuf, err := utils.GetBytes(buf, int(ln)); err != nil {
					return nil, fmt.Errorf("%s: %w", opKinds[int(t)], err)
				} else {
					for len(pbuf) != 0 {
						p, err := utils.GetBytes(&pbuf, 32)
						if err != nil {
							return nil, fmt.Errorf("%s: %w", opKinds[int(t)], err)
						}
						op.MessagePath = append(op.MessagePath, encodeBase58(pInboxListHash, p))
					}
				}
				if r, err := utils.GetBytes(buf, 32); err != nil {
					return nil, fmt.Errorf("%s: %w", opKinds[int(t)], err)
				} else {
					op.MessageResultHash = encodeBase58(pMessageResultHash, r)
				}

				if ln, err = utils.GetUint32(buf); err != nil {
					return nil, fmt.Errorf("%s: %w", opKinds[int(t)], err)
				}
				if pbuf, err := utils.GetBytes(buf, int(ln)); err != nil {
					return nil, fmt.Errorf("%s: %w", opKinds[int(t)], err)
				} else {
					for len(pbuf) != 0 {
						p, err := utils.GetBytes(&pbuf, 32)
						if err != nil {
							return nil, fmt.Errorf("%s: %w", opKinds[int(t)], err)
						}
						op.MessageResultPath = append(op.MessageResultPath, encodeBase58(pMessageResultListHash, p))
					}
				}
				if v, err := utils.GetBytes(buf, 32); err != nil {
					return nil, fmt.Errorf("%s: %w", opKinds[int(t)], err)
				} else {
					op.PreviousMessageResult.ContextHash = encodeBase58(pContextHash, v)
				}
				if v, err := utils.GetBytes(buf, 32); err != nil {
					return nil, fmt.Errorf("%s: %w", opKinds[int(t)], err)
				} else {
					op.PreviousMessageResult.WithdrawListHash = encodeBase58(pWithdrawListHash, v)
				}
				if ln, err = utils.GetUint32(buf); err != nil {
					return nil, fmt.Errorf("%s: %w", opKinds[int(t)], err)
				}
				if pbuf, err := utils.GetBytes(buf, int(ln)); err != nil {
					return nil, fmt.Errorf("%s: %w", opKinds[int(t)], err)
				} else {
					for len(pbuf) != 0 {
						p, err := utils.GetBytes(&pbuf, 32)
						if err != nil {
							return nil, fmt.Errorf("%s: %w", opKinds[int(t)], err)
						}
						op.PreviousMessageResultPath = append(op.PreviousMessageResultPath, encodeBase58(pMessageResultListHash, p))
					}
				}

				// The binary proof encoding is not documented well and surprisingly doesn't reflect JSON that much to use
				// latter as a reference
				if _, err := utils.GetBytes(buf, 1+2+32+32); err != nil {
					return nil, fmt.Errorf("%s: %w", opKinds[int(t)], err)
				}
				if ln, err = utils.GetUint32(buf); err != nil {
					return nil, fmt.Errorf("%s: %w", opKinds[int(t)], err)
				}
				if _, err := utils.GetBytes(buf, int(ln)); err != nil {
					return nil, fmt.Errorf("%s: %w", opKinds[int(t)], err)
				}
				return &op, nil

			case tagTxRollupDispatchTickets:
				op := OpTxRollupDispatchTickets{
					Rollup: rollup,
				}
				if op.Level, err = utils.GetInt32(buf); err != nil {
					return nil, fmt.Errorf("%s: %w", opKinds[int(t)], err)
				}
				if v, err := utils.GetBytes(buf, 32); err != nil {
					return nil, fmt.Errorf("%s: %w", opKinds[int(t)], err)
				} else {
					op.ContextHash = encodeBase58(pContextHash, v)
				}
				if op.MessageIndex, err = utils.GetInt32(buf); err != nil {
					return nil, fmt.Errorf("%s: %w", opKinds[int(t)], err)
				}
				ln, err := utils.GetUint32(buf)
				if err != nil {
					return nil, fmt.Errorf("%s: %w", opKinds[int(t)], err)
				}
				if pbuf, err := utils.GetBytes(buf, int(ln)); err != nil {
					return nil, fmt.Errorf("%s: %w", opKinds[int(t)], err)
				} else {
					for len(pbuf) != 0 {
						p, err := utils.GetBytes(&pbuf, 32)
						if err != nil {
							return nil, fmt.Errorf("%s: %w", opKinds[int(t)], err)
						}
						op.MessageResultPath = append(op.MessageResultPath, encodeBase58(pMessageResultListHash, p))
					}
				}
				if ln, err = utils.GetUint32(buf); err != nil {
					return nil, fmt.Errorf("%s: %w", opKinds[int(t)], err)
				}
				if tibuf, err := utils.GetBytes(buf, int(ln)); err != nil {
					return nil, fmt.Errorf("%s: %w", opKinds[int(t)], err)
				} else {
					for len(tibuf) != 0 {
						var ti TicketInfo
						if ln, err = utils.GetUint32(&tibuf); err != nil {
							return nil, fmt.Errorf("%s: %w", opKinds[int(t)], err)
						}
						if ti.Contents, err = utils.GetBytes(&tibuf, int(ln)); err != nil {
							return nil, fmt.Errorf("%s: %w", opKinds[int(t)], err)
						}
						if ln, err = utils.GetUint32(&tibuf); err != nil {
							return nil, fmt.Errorf("%s: %w", opKinds[int(t)], err)
						}
						if ti.Ty, err = utils.GetBytes(&tibuf, int(ln)); err != nil {
							return nil, fmt.Errorf("%s: %w", opKinds[int(t)], err)
						}
						if ti.Ticketer, err = parseDestination(&tibuf); err != nil {
							return nil, fmt.Errorf("%s: %w", opKinds[int(t)], err)
						}
						if ti.Amount, err = parseAmount(&tibuf); err != nil {
							return nil, fmt.Errorf("%s: %w", opKinds[int(t)], err)
						}
						if ti.Claimer, err = parsePublicKeyHash(&tibuf); err != nil {
							return nil, fmt.Errorf("%s: %w", opKinds[int(t)], err)
						}
						op.TicketsInfo = append(op.TicketsInfo, ti)
					}
				}
				return &op, nil
			}

		case tagTransferTicket:
			op := OpTransferTicket{
				Manager: common,
			}
			ln, err := utils.GetUint32(buf)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", opKinds[int(t)], err)
			}
			if op.TicketContents, err = utils.GetBytes(buf, int(ln)); err != nil {
				return nil, fmt.Errorf("%s: %w", opKinds[int(t)], err)
			}
			if ln, err = utils.GetUint32(buf); err != nil {
				return nil, fmt.Errorf("%s: %w", opKinds[int(t)], err)
			}
			if op.TicketTy, err = utils.GetBytes(buf, int(ln)); err != nil {
				return nil, fmt.Errorf("%s: %w", opKinds[int(t)], err)
			}
			if op.TicketTicketer, err = parseDestination(buf); err != nil {
				return nil, fmt.Errorf("%s: %w", opKinds[int(t)], err)
			}
			if op.TicketAmount, err = parseBigUint(buf); err != nil {
				return nil, fmt.Errorf("%s: %w", opKinds[int(t)], err)
			}
			if op.Destination, err = parseDestination(buf); err != nil {
				return nil, fmt.Errorf("%s: %w", opKinds[int(t)], err)
			}
			if ln, err = utils.GetUint32(buf); err != nil {
				return nil, fmt.Errorf("%s: %w", opKinds[int(t)], err)
			}
			if v, err := utils.GetBytes(buf, int(ln)); err != nil {
				return nil, fmt.Errorf("%s: %w", opKinds[int(t)], err)
			} else {
				op.Entrypoint = string(v)
			}
			return &op, nil

		case tagScRollupOriginate:
			op := OpScRollupOriginate{
				Manager: common,
			}
			if op.Kind, err = utils.GetUint16(buf); err != nil {
				return nil, fmt.Errorf("%s: %w", opKinds[int(t)], err)
			}
			ln, err := utils.GetUint32(buf)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", opKinds[int(t)], err)
			}
			if bs, err := utils.GetBytes(buf, int(ln)); err != nil {
				return nil, fmt.Errorf("%s: %w", opKinds[int(t)], err)
			} else {
				op.BootSector = string(bs)
			}
			return &op, nil

		case tagScRollupAddMessages:
			op := OpScRollupAddMessages{
				Manager: common,
			}
			ln, err := utils.GetUint32(buf)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", opKinds[int(t)], err)
			}
			if v, err := utils.GetBytes(buf, int(ln)); err != nil {
				return nil, fmt.Errorf("%s: %w", opKinds[int(t)], err)
			} else {
				op.Rollup = encodeBase58(pScRollupHash, v)
			}
			if ln, err = utils.GetUint32(buf); err != nil {
				return nil, fmt.Errorf("%s: %w", opKinds[int(t)], err)
			}
			if mbuf, err := utils.GetBytes(buf, int(ln)); err != nil {
				return nil, fmt.Errorf("%s: %w", opKinds[int(t)], err)
			} else {
				for len(mbuf) != 0 {
					ln, err := utils.GetUint32(buf)
					if err != nil {
						return nil, fmt.Errorf("%s: %w", opKinds[int(t)], err)
					}
					if m, err := utils.GetBytes(buf, int(ln)); err != nil {
						return nil, fmt.Errorf("%s: %w", opKinds[int(t)], err)
					} else {
						op.Message = append(op.Message, string(m))
					}
				}
			}
			return &op, nil

		case tagScRollupCement:
			op := OpScRollupCement{
				Manager: common,
			}
			ln, err := utils.GetUint32(buf)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", opKinds[int(t)], err)
			}
			if v, err := utils.GetBytes(buf, int(ln)); err != nil {
				return nil, fmt.Errorf("%s: %w", opKinds[int(t)], err)
			} else {
				op.Rollup = encodeBase58(pScRollupHash, v)
			}
			if v, err := utils.GetBytes(buf, 32); err != nil {
				return nil, fmt.Errorf("%s: %w", opKinds[int(t)], err)
			} else {
				op.Commitment = encodeBase58(pScCommitmentHash, v)
			}
			return &op, nil

		case tagScRollupPublish:
			op := OpScRollupPublish{
				Manager: common,
			}
			ln, err := utils.GetUint32(buf)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", opKinds[int(t)], err)
			}
			if v, err := utils.GetBytes(buf, int(ln)); err != nil {
				return nil, fmt.Errorf("%s: %w", opKinds[int(t)], err)
			} else {
				op.Rollup = encodeBase58(pScRollupHash, v)
			}
			if v, err := utils.GetBytes(buf, 32); err != nil {
				return nil, fmt.Errorf("%s: %w", opKinds[int(t)], err)
			} else {
				op.Commitment.CompressedState = encodeBase58(pScStateHash, v)
			}
			if op.Commitment.InboxLevel, err = utils.GetInt32(buf); err != nil {
				return nil, fmt.Errorf("%s: %w", opKinds[int(t)], err)
			}
			if v, err := utils.GetBytes(buf, 32); err != nil {
				return nil, fmt.Errorf("%s: %w", opKinds[int(t)], err)
			} else {
				op.Commitment.Predecessor = encodeBase58(pScCommitmentHash, v)
			}
			if op.Commitment.NumberOfMessages, err = utils.GetInt32(buf); err != nil {
				return nil, fmt.Errorf("%s: %w", opKinds[int(t)], err)
			}
			if op.Commitment.NumberOfTicks, err = utils.GetInt32(buf); err != nil {
				return nil, fmt.Errorf("%s: %w", opKinds[int(t)], err)
			}
			return &op, nil
		}
	}

	return nil, fmt.Errorf("tezos: unknown or unimplemented operation tag: %d", t)
}

func parseAmount(buf *[]byte) (int64, error) {
	tag, err := utils.GetByte(buf)
	if err != nil {
		return 0, fmt.Errorf("amount: %w", err)
	}
	switch tag {
	case 0:
		v, err := utils.GetByte(buf)
		if err != nil {
			return 0, fmt.Errorf("amount: %w", err)
		}
		return int64(v), nil
	case 1:
		v, err := utils.GetUint16(buf)
		if err != nil {
			return 0, fmt.Errorf("amount: %w", err)
		}
		return int64(v), nil
	case 2:
		v, err := utils.GetInt32(buf)
		if err != nil {
			return 0, fmt.Errorf("amount: %w", err)
		}
		return int64(v), nil
	case 3:
		v, err := utils.GetInt64(buf)
		if err != nil {
			return 0, fmt.Errorf("amount: %w", err)
		}
		return v, nil
	default:
		return 0, fmt.Errorf("amount: unexpected tag %d", tag)
	}
}

func parseInlinedEndorsement(buf *[]byte) (*InlinedEndorsement, error) {
	blockHash, err := utils.GetBytes(buf, 32)
	if err != nil {
		return nil, fmt.Errorf("inlined_endorsement: %w", err)
	}
	op, err := parseOperation(buf)
	if err != nil {
		return nil, fmt.Errorf("inlined_endorsement: %w", err)
	}
	e, ok := op.(Endorsement)
	if !ok {
		return nil, fmt.Errorf("tezos: endorsement operation expected, got: %T", op)
	}
	return &InlinedEndorsement{
		Endorsement: e,
		Branch:      encodeBase58(pBlockHash, blockHash),
		Signature:   encodeBase58(pGenericSignature, *buf),
	}, nil
}

func parseInlinedPreendorsement(buf *[]byte) (*InlinedPreendorsement, error) {
	blockHash, err := utils.GetBytes(buf, 32)
	if err != nil {
		return nil, fmt.Errorf("inlined_preendorsement: %w", err)
	}
	op, err := parseOperation(buf)
	if err != nil {
		return nil, fmt.Errorf("inlined_preendorsement: %w", err)
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
	tagPublicKeyHashBLS12_381
)

func parsePublicKeyHash(buf *[]byte) (pkh string, err error) {
	t, err := utils.GetByte(buf)
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
	case tagPublicKeyHashBLS12_381:
		prefix = pBLS12_381PublicKeyHash
	default:
		return "", fmt.Errorf("tezos: unknown public key hash tag: %d", t)
	}

	b, err := utils.GetBytes(buf, 20)
	if err != nil {
		return "", err
	}

	return encodeBase58(prefix, b), nil
}

const (
	tagPublicKeyED25519 = iota
	tagPublicKeySECP256K1
	tagPublicKeyP256
	tagPublicKeyBLS12_381
)

func parsePublicKey(buf *[]byte) (pkh string, err error) {
	t, err := utils.GetByte(buf)
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
	case tagPublicKeyBLS12_381:
		prefix = pBLS12_381PublicKey
		ln = 48
	default:
		return "", fmt.Errorf("tezos: unknown public key tag: %d", t)
	}

	b, err := utils.GetBytes(buf, ln)
	if err != nil {
		return "", err
	}
	return encodeBase58(prefix, b), nil
}

const (
	tagDestinationImplicit = iota
	tagDestinationOriginated
	tagDestinationTxRollup
)

func parseDestination(buf *[]byte) (pkh string, err error) {
	t, err := utils.GetByte(buf)
	if err != nil {
		return "", err
	}

	switch t {
	case tagDestinationImplicit:
		pkh, err = parsePublicKeyHash(buf)
		if err != nil {
			return "", err
		}
		return pkh, nil

	case tagDestinationOriginated:
		b, err := utils.GetBytes(buf, 20)
		if err != nil {
			return "", err
		}
		pkh = encodeBase58(pContractHash, b)
		_, err = utils.GetByte(buf)
		return pkh, err

	case tagDestinationTxRollup:
		b, err := utils.GetBytes(buf, 20)
		if err != nil {
			return "", err
		}
		pkh = encodeBase58(pRollupAddress, b)
		_, err = utils.GetByte(buf)
		return pkh, err
	}

	return "", fmt.Errorf("tezos: unknown contract id tag: %d", t)
}

func parseBigUint(buf *[]byte) (val *big.Int, err error) {
	res := big.NewInt(0)
	shift := uint(0)
	for {
		b, err := utils.GetByte(buf)
		if err != nil {
			return nil, err
		}
		tmp := big.NewInt(int64(b & 0x7f))
		tmp.Lsh(tmp, shift)
		res.Or(res, tmp)
		shift += 7
		if b&0x80 == 0 {
			return res, nil
		}
	}
}

func parseBigInt(buf *[]byte) (val *big.Int, err error) {
	b, err := utils.GetByte(buf)
	if err != nil {
		return nil, err
	}
	var sign int
	if b&0x40 != 0 {
		sign = -1
	} else {
		sign = 1
	}
	res := big.NewInt(int64(b & 0x3f))
	if b&0x80 == 0 {
		if sign < 0 {
			res.Neg(res)
		}
		return res, nil
	}
	shift := uint(6)
	for {
		b, err := utils.GetByte(buf)
		if err != nil {
			return nil, err
		}
		tmp := big.NewInt(int64(b & 0x7f))
		tmp.Lsh(tmp, shift)
		res.Or(res, tmp)
		shift += 7
		if b&0x80 == 0 {
			if sign < 0 {
				res.Neg(res)
			}
			return res, nil
		}
	}
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
	t, err := utils.GetByte(buf)
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
		ln, err := utils.GetByte(buf)
		if err != nil {
			return "", err
		}
		name, err := utils.GetBytes(buf, int(ln))
		if err != nil {
			return "", err
		}
		e = string(name)
	default:
		return "", fmt.Errorf("tezos: unknown entrypoint tag: %d", t)
	}
	return e, nil
}

var operations = []Operation{
	&OpEmmyEndorsement{},
	&OpSeedNonceRevelation{},
	&OpDoubleEndorsementEvidence{},
	&OpDoubleBakingEvidence{},
	&OpActivateAccount{},
	&OpProposals{},
	&OpBallot{},
	&OpDoublePreendorsementEvidence{},
	&OpEndorsementWithSlot{},
	&OpFailingNoop{},
	&OpPreendorsement{},
	&OpTenderbakeEndorsement{},
	&OpReveal{},
	&OpTransaction{},
	&OpOrigination{},
	&OpDelegation{},
	&OpRegisterGlobalConstant{},
	&OpSetDepositsLimit{},
	&OpTxRollupOrigination{},
	&OpTxRollupSubmitBatch{},
	&OpTxRollupCommit{},
	&OpTxRollupReturnBond{},
	&OpTxRollupFinalizeCommitment{},
	&OpTxRollupRemoveCommitment{},
	&OpTxRollupRejection{},
	&OpTxRollupDispatchTickets{},
	&OpTransferTicket{},
	&OpScRollupOriginate{},
	&OpScRollupAddMessages{},
	&OpScRollupCement{},
	&OpScRollupPublish{},
}

var Operations []string

func init() {
	ops := make(map[string]bool, len(operations))
	for _, r := range operations {
		ops[r.OperationKind()] = true
	}
	Operations = make([]string, 0, len(ops))
	for op := range ops {
		Operations = append(Operations, op)
	}
	sort.Strings(Operations)
}
