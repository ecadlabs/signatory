// gen-test-payloads generates Tezos sign request test payloads for signatory integration tests.
//
// Field values are sourced from mainnet blocks to preserve provenance.
// The sandbox chain_id (NetXo5iVw1vBoxM / b3d79f99) is used because
// integration tests run against a sandbox, not mainnet.
//
// Usage: go run ./cmd/gen-test-payloads/
package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log"
	"os"

	tz "github.com/ecadlabs/gotez/v2"
	"github.com/ecadlabs/gotez/v2/encoding"
	"github.com/ecadlabs/gotez/v2/protocol/core"
	latest "github.com/ecadlabs/gotez/v2/protocol/latest"
	"golang.org/x/crypto/blake2b"
)

func mustParseBlockHash(s string) *tz.BlockHash {
	var h tz.BlockHash
	if err := h.UnmarshalText([]byte(s)); err != nil {
		log.Fatalf("parse BlockHash %q: %v", s, err)
	}
	return &h
}

func mustParseOpsHash(s string) *tz.OperationsHash {
	var h tz.OperationsHash
	if err := h.UnmarshalText([]byte(s)); err != nil {
		log.Fatalf("parse OperationsHash %q: %v", s, err)
	}
	return &h
}

func mustParseContextHash(s string) *tz.ContextHash {
	var h tz.ContextHash
	if err := h.UnmarshalText([]byte(s)); err != nil {
		log.Fatalf("parse ContextHash %q: %v", s, err)
	}
	return &h
}

func mustParsePayloadHash(s string) *tz.BlockPayloadHash {
	var h tz.BlockPayloadHash
	if err := h.UnmarshalText([]byte(s)); err != nil {
		log.Fatalf("parse BlockPayloadHash %q: %v", s, err)
	}
	return &h
}

func mustParseChainID(s string) *tz.ChainID {
	var c tz.ChainID
	if err := c.UnmarshalText([]byte(s)); err != nil {
		log.Fatalf("parse ChainID %q: %v", s, err)
	}
	return &c
}

func mustParseBytes8(hexStr string) *tz.Bytes8 {
	b, err := hex.DecodeString(hexStr)
	if err != nil || len(b) != 8 {
		log.Fatalf("parse Bytes8 hex %q: err=%v len=%d", hexStr, err, len(b))
	}
	var result tz.Bytes8
	copy(result[:], b)
	return &result
}

// buildFitness constructs Tenderbake fitness bytes (the inner bytes, without
// the outer 4-byte dynamic length prefix which gotez adds via tz:"dyn").
//
// Binary layout:
//
//	<version_len(4)><version(1)>
//	<level_len(4)><level(4)>
//	<locked_round_len(4)>[locked_round(4)]
//	<pred_round_len(4)><pred_round(4)>
//	<round_len(4)><round(4)>
func buildFitness(level int32, lockedRound *int32, predRound int32, round int32) tz.Bytes {
	var buf bytes.Buffer
	w := func(v any) {
		if err := binary.Write(&buf, binary.BigEndian, v); err != nil {
			log.Fatalf("binary.Write: %v", err)
		}
	}

	// Version: len=1, val=0x02 (Tenderbake)
	w(uint32(1))
	buf.WriteByte(0x02)

	// Level
	w(uint32(4))
	w(level)

	// Locked round (optional)
	if lockedRound != nil {
		w(uint32(4))
		w(*lockedRound)
	} else {
		w(uint32(0))
	}

	// Predecessor round
	w(uint32(4))
	w(predRound)

	// Round (this is what GetRoundFromTenderbakeBlock reads: last 4 bytes)
	w(uint32(4))
	w(round)

	return buf.Bytes()
}

// encodeSignRequest encodes a sign request to bytes and returns the hex string.
func encodeSignRequest(sr latest.SignRequest) []byte {
	var buf bytes.Buffer
	if err := encoding.Encode(&buf, &sr); err != nil {
		log.Fatalf("encoding.Encode: %v", err)
	}
	return buf.Bytes()
}

// decodeAndVerifyBlock decodes a block sign request and prints verification info.
func decodeAndVerifyBlock(data []byte, label string, expectLevel int32, expectFitnessRound int32, expectPayloadRound int32) {
	var sr latest.SignRequest
	rest, err := encoding.Decode(data, &sr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "  ERROR: decode %s: %v\n", label, err)
		return
	}
	if len(rest) != 0 {
		fmt.Fprintf(os.Stderr, "  ERROR: %s: %d bytes remaining after decode\n", label, len(rest))
		return
	}
	bsr, ok := sr.(*latest.BlockSignRequest)
	if !ok {
		fmt.Fprintf(os.Stderr, "  ERROR: %s: expected *BlockSignRequest, got %T\n", label, sr)
		return
	}
	level := bsr.GetLevel()
	fitnessRound := bsr.GetRound()
	payloadRound := bsr.BlockHeader.PayloadRound

	ok = true
	if level != expectLevel {
		fmt.Fprintf(os.Stderr, "  MISMATCH %s: level got=%d want=%d\n", label, level, expectLevel)
		ok = false
	}
	if fitnessRound != expectFitnessRound {
		fmt.Fprintf(os.Stderr, "  MISMATCH %s: fitness_round got=%d want=%d\n", label, fitnessRound, expectFitnessRound)
		ok = false
	}
	if payloadRound != expectPayloadRound {
		fmt.Fprintf(os.Stderr, "  MISMATCH %s: payload_round got=%d want=%d\n", label, payloadRound, expectPayloadRound)
		ok = false
	}
	if ok {
		fmt.Printf("  Decode verify: OK (level=%d, fitness_round=%d, payload_round=%d)\n", level, fitnessRound, payloadRound)
	}
}

// decodeAndVerifyConsensus decodes a preattestation/attestation sign request and verifies.
func decodeAndVerifyConsensus(data []byte, label string, expectLevel int32, expectRound int32, expectSlot uint16, expectKind string) {
	var sr latest.SignRequest
	rest, err := encoding.Decode(data, &sr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "  ERROR: decode %s: %v\n", label, err)
		return
	}
	if len(rest) != 0 {
		fmt.Fprintf(os.Stderr, "  ERROR: %s: %d bytes remaining after decode\n", label, len(rest))
		return
	}

	kind := sr.SignRequestKind()
	if kind != expectKind {
		fmt.Fprintf(os.Stderr, "  MISMATCH %s: kind got=%q want=%q\n", label, kind, expectKind)
	}

	type levelRoundGetter interface {
		GetLevel() int32
		GetRound() int32
	}
	if lrg, ok := sr.(levelRoundGetter); ok {
		level := lrg.GetLevel()
		round := lrg.GetRound()
		match := true
		if level != expectLevel {
			fmt.Fprintf(os.Stderr, "  MISMATCH %s: level got=%d want=%d\n", label, level, expectLevel)
			match = false
		}
		if round != expectRound {
			fmt.Fprintf(os.Stderr, "  MISMATCH %s: round got=%d want=%d\n", label, round, expectRound)
			match = false
		}
		if match {
			fmt.Printf("  Decode verify: OK (kind=%s, level=%d, round=%d)\n", kind, level, round)
		}
	}
}

func printPayload(label string, data []byte, provenance string) {
	h := blake2b.Sum256(data)
	fmt.Printf("\n=== %s ===\n", label)
	fmt.Printf("  Provenance: %s\n", provenance)
	fmt.Printf("  Hex (%d bytes):\n    %s\n", len(data), hex.EncodeToString(data))
	fmt.Printf("  Blake2b-256: %s\n", hex.EncodeToString(h[:]))
}

func main() {
	// Sandbox chain_id used by integration tests
	chainID := mustParseChainID("NetXo5iVw1vBoxM")
	fmt.Printf("Chain ID: NetXo5iVw1vBoxM = %s\n", hex.EncodeToString(chainID[:]))

	// =========================================================================
	// Mainnet block data sources (fetched 2026-03-03 via ECAD RPC)
	//
	// Block 12180922 (hash: BL6N1Gyj4BQM7PKHBoFZkpWMJFgtxBe1UmAJYw2hcRwPqzzD8Mw)
	//   https://mainnet.ecadinfra.com/chains/main/blocks/12180922/header
	//   proto=24, fitness=["02","00b9ddba","","ffffffff","00000000"]
	//   timestamp=2026-03-03T20:43:31Z, payload_round=0, validation_pass=4
	//
	// Block 12180921 (hash: BLr2oQRyp4KdRHuLLWnPXCXW1DKeqAbLbof5n8BZcdzrxQ4WR2C)
	//   https://mainnet.ecadinfra.com/chains/main/blocks/12180921/header
	//   proto=24, fitness=["02","00b9ddb9","","ffffffff","00000000"]
	//   timestamp=2026-03-03T20:43:25Z, payload_round=0, validation_pass=4
	//
	// Block 12180920 (hash: BMUGMyDmR5UzVMcLhE3x6Kghpy9i92qA8NjyTSiW9FstYejfcYM)
	//   https://mainnet.ecadinfra.com/chains/main/blocks/12180920/header
	//   proto=24, fitness=["02","00b9ddb8","","ffffffff","00000000"]
	//   timestamp=2026-03-03T20:43:19Z, payload_round=0, validation_pass=4
	// =========================================================================

	// Field values from mainnet block 12180922
	pred922 := mustParseBlockHash("BLr2oQRyp4KdRHuLLWnPXCXW1DKeqAbLbof5n8BZcdzrxQ4WR2C")
	ops922 := mustParseOpsHash("LLoZnByngpdCJvQYcR2NVfh5yQMNdhsDBonRRSMLnjQ2bBPhu91eK")
	ctx922 := mustParseContextHash("CoWSaFewEk5ahyKcD6GtuUd3zFoPYu42MrnahXAUQVgBAWHZs3DH")
	ph922 := mustParsePayloadHash("vh2Ly5SQoVL3LDCD6eS2Bddd5u7dxbgaHocrM5cwEzfpfMMRCmDT")
	pow922 := mustParseBytes8("d7d4b0aea9d00000")
	ts922 := tz.Timestamp(1772667811) // 2026-03-03T20:43:31Z

	// Field values from mainnet block 12180921
	pred921 := mustParseBlockHash("BMUGMyDmR5UzVMcLhE3x6Kghpy9i92qA8NjyTSiW9FstYejfcYM")
	ops921 := mustParseOpsHash("LLoZdvFC5FUhR6pQPPiw5h9Wpe95FVWPgHe9xPiJ4BRycw3zV9tmw")
	ctx921 := mustParseContextHash("CoVbLWUe7zwHNMPUkn4b3f8cj5YGbC84MVeHfJYWiSKD127rqegV")
	ph921 := mustParsePayloadHash("vh1hscJouzKCgX7UGeLdHVNqDTwu7dX25ZaBSDJRdMK7tvMgpBzt")
	pow921 := mustParseBytes8("5a3ca147d36b0200")
	ts921 := tz.Timestamp(1772667805) // 2026-03-03T20:43:25Z

	// Field values from mainnet block 12180920
	pred920 := mustParseBlockHash("BLEsEMqPyc4ZKK28dRNTviccxQeCXyG9mEhY7kCGkqpWf5BvBQa")
	ops920 := mustParseOpsHash("LLoZevF5Tq8n68YaBazkLxdAYLScaafu7kQd7WdvDnY3N2vxMJXPx")
	ctx920 := mustParseContextHash("CoW65CnDaQjsC7Xoszz9JEJ6dVUTvDNrabJohd4hGyf2KFuzQxCH")
	ph920 := mustParsePayloadHash("vh1wDvy7YHD4ytmaQc7DBvmdzk7dj2K1afAhrnQR65hBApLZybWu")
	pow920 := mustParseBytes8("5a3ca14768060100")
	ts920 := tz.Timestamp(1772667799) // 2026-03-03T20:43:19Z

	// Block hash from block 12180922, used as branch for consensus operations
	branch922 := mustParseBlockHash("BL6N1Gyj4BQM7PKHBoFZkpWMJFgtxBe1UmAJYw2hcRwPqzzD8Mw")

	// =========================================================================
	// Group A: Double-bake detection (level 2, fitness round 0)
	// Two blocks at the same (level=2, fitness_round=0) with different content.
	// =========================================================================

	// A1: Block at level=2, fitness_round=0, payload_round=0
	// Base field values from mainnet block 12180922
	a1 := &latest.BlockSignRequest{
		Chain: chainID,
		BlockHeader: latest.UnsignedBlockHeader{
			ShellHeader: core.ShellHeader{
				Level:          2,
				Proto:          24,
				Predecessor:    pred922,
				Timestamp:      ts922,
				ValidationPass: 4,
				OperationsHash: ops922,
				Fitness:        buildFitness(2, nil, -1, 0),
				Context:        ctx922,
			},
			UnsignedProtocolBlockHeader: latest.UnsignedProtocolBlockHeader{
				PayloadHash:      ph922,
				PayloadRound:     0,
				ProofOfWorkNonce: pow922,
				SeedNonceHash:    tz.None[*tz.CycleNonceHash](),
				PerBlockVotes:    0,
			},
		},
	}

	// A2: Block at level=2, fitness_round=0, payload_round=0
	// DIFFERENT content (different predecessor, ops_hash, timestamp, context, payload_hash)
	// sourced from mainnet block 12180921 -- true double-bake with A1
	a2 := &latest.BlockSignRequest{
		Chain: chainID,
		BlockHeader: latest.UnsignedBlockHeader{
			ShellHeader: core.ShellHeader{
				Level:          2,
				Proto:          24,
				Predecessor:    pred921,
				Timestamp:      ts921,
				ValidationPass: 4,
				OperationsHash: ops921,
				Fitness:        buildFitness(2, nil, -1, 0),
				Context:        ctx921,
			},
			UnsignedProtocolBlockHeader: latest.UnsignedProtocolBlockHeader{
				PayloadHash:      ph921,
				PayloadRound:     0,
				ProofOfWorkNonce: pow921,
				SeedNonceHash:    tz.None[*tz.CycleNonceHash](),
				PerBlockVotes:    0,
			},
		},
	}

	// =========================================================================
	// Group B: Level advance (level 7, fitness round 2)
	// Two blocks at the same (level=7, fitness_round=2) with different content.
	// Fresh proposals (payload_round == fitness_round).
	// =========================================================================

	// B1: Block at level=7, fitness_round=2, payload_round=2
	// Base field values from mainnet block 12180920
	b1 := &latest.BlockSignRequest{
		Chain: chainID,
		BlockHeader: latest.UnsignedBlockHeader{
			ShellHeader: core.ShellHeader{
				Level:          7,
				Proto:          24,
				Predecessor:    pred920,
				Timestamp:      ts920,
				ValidationPass: 4,
				OperationsHash: ops920,
				Fitness:        buildFitness(7, nil, -1, 2),
				Context:        ctx920,
			},
			UnsignedProtocolBlockHeader: latest.UnsignedProtocolBlockHeader{
				PayloadHash:      ph920,
				PayloadRound:     2,
				ProofOfWorkNonce: pow920,
				SeedNonceHash:    tz.None[*tz.CycleNonceHash](),
				PerBlockVotes:    0,
			},
		},
	}

	// B2: Block at level=7, fitness_round=2, payload_round=2
	// DIFFERENT content sourced from mainnet block 12180921 -- true double-bake with B1
	b2 := &latest.BlockSignRequest{
		Chain: chainID,
		BlockHeader: latest.UnsignedBlockHeader{
			ShellHeader: core.ShellHeader{
				Level:          7,
				Proto:          24,
				Predecessor:    pred921,
				Timestamp:      ts921,
				ValidationPass: 4,
				OperationsHash: ops921,
				Fitness:        buildFitness(7, nil, -1, 2),
				Context:        ctx921,
			},
			UnsignedProtocolBlockHeader: latest.UnsignedProtocolBlockHeader{
				PayloadHash:      ph921,
				PayloadRound:     2,
				ProofOfWorkNonce: pow921,
				SeedNonceHash:    tz.None[*tz.CycleNonceHash](),
				PerBlockVotes:    0,
			},
		},
	}

	// =========================================================================
	// Group C: Happy path baking (level 34, fitness round 4)
	// One block, one preattestation, one attestation.
	// =========================================================================

	// C1: Block at level=34, fitness_round=4, payload_round=4
	// Base field values from mainnet block 12180922
	c1 := &latest.BlockSignRequest{
		Chain: chainID,
		BlockHeader: latest.UnsignedBlockHeader{
			ShellHeader: core.ShellHeader{
				Level:          34,
				Proto:          24,
				Predecessor:    pred922,
				Timestamp:      ts922,
				ValidationPass: 4,
				OperationsHash: ops922,
				Fitness:        buildFitness(34, nil, -1, 4),
				Context:        ctx922,
			},
			UnsignedProtocolBlockHeader: latest.UnsignedProtocolBlockHeader{
				PayloadHash:      ph922,
				PayloadRound:     4,
				ProofOfWorkNonce: pow922,
				SeedNonceHash:    tz.None[*tz.CycleNonceHash](),
				PerBlockVotes:    0,
			},
		},
	}

	// C2: Preattestation at level=34, round=4, slot=20
	// Branch from mainnet block 12180922 hash, payload_hash from same block
	c2 := &latest.PreattestationSignRequest{
		Chain:  chainID,
		Branch: branch922,
		Operation: &latest.Preattestation{
			Slot:             20,
			Level:            34,
			Round:            4,
			BlockPayloadHash: ph922,
		},
	}

	// C3: Attestation at level=34, round=4, slot=21
	// Branch from mainnet block 12180922 hash, payload_hash from same block
	c3 := &latest.AttestationSignRequest{
		Chain:  chainID,
		Branch: branch922,
		Operation: &latest.Attestation{
			Slot:             21,
			Level:            34,
			Round:            4,
			BlockPayloadHash: ph922,
		},
	}

	// =========================================================================
	// Encode and output all payloads
	// =========================================================================

	type payload struct {
		label      string
		sr         latest.SignRequest
		provenance string
	}

	payloads := []payload{
		{"A1", a1, "block fields from mainnet 12180922; level=2 fitness_round=0 payload_round=0"},
		{"A2", a2, "block fields from mainnet 12180921; level=2 fitness_round=0 payload_round=0 (double-bake with A1)"},
		{"B1", b1, "block fields from mainnet 12180920; level=7 fitness_round=2 payload_round=2"},
		{"B2", b2, "block fields from mainnet 12180921; level=7 fitness_round=2 payload_round=2 (double-bake with B1)"},
		{"C1", c1, "block fields from mainnet 12180922; level=34 fitness_round=4 payload_round=4"},
		{"C2", c2, "preattestation level=34 round=4 slot=20; branch=mainnet block 12180922 hash"},
		{"C3", c3, "attestation level=34 round=4 slot=21; branch=mainnet block 12180922 hash"},
	}

	hadError := false
	for _, p := range payloads {
		data := encodeSignRequest(p.sr)
		printPayload(p.label, data, p.provenance)

		switch p.label {
		case "A1":
			decodeAndVerifyBlock(data, p.label, 2, 0, 0)
		case "A2":
			decodeAndVerifyBlock(data, p.label, 2, 0, 0)
		case "B1":
			decodeAndVerifyBlock(data, p.label, 7, 2, 2)
		case "B2":
			decodeAndVerifyBlock(data, p.label, 7, 2, 2)
		case "C1":
			decodeAndVerifyBlock(data, p.label, 34, 4, 4)
		case "C2":
			decodeAndVerifyConsensus(data, p.label, 34, 4, 20, "preattestation")
		case "C3":
			decodeAndVerifyConsensus(data, p.label, 34, 4, 21, "attestation")
		}
	}

	// Verify A1 and A2 produce different blake2b hashes (different blocks at same level/round)
	a1data := encodeSignRequest(a1)
	a2data := encodeSignRequest(a2)
	a1hash := blake2b.Sum256(a1data)
	a2hash := blake2b.Sum256(a2data)
	fmt.Printf("\n=== Double-bake verification ===\n")
	fmt.Printf("  A1 != A2: %v (different block content at same level=2, round=0)\n", a1hash != a2hash)
	b1data := encodeSignRequest(b1)
	b2data := encodeSignRequest(b2)
	b1hash := blake2b.Sum256(b1data)
	b2hash := blake2b.Sum256(b2data)
	fmt.Printf("  B1 != B2: %v (different block content at same level=7, round=2)\n", b1hash != b2hash)

	if a1hash == a2hash || b1hash == b2hash {
		fmt.Fprintf(os.Stderr, "\nFATAL: double-bake pairs must have different hashes!\n")
		hadError = true
	}

	if hadError {
		os.Exit(1)
	}

	_ = pred920
	_ = ops920
	_ = ctx920
	_ = ph920
	_ = pow920
	_ = ts920
}
