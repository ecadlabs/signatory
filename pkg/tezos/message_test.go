//go:build !integration

package tezos

import (
	"encoding/hex"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func mustHex(s string) []byte {
	buf, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return buf
}

// Forged test cases
func TestUnsignedOperations(t *testing.T) {
	type testCase struct {
		data []byte
		op   *UnsignedOperation
	}

	var cases = []testCase{
		{
			data: mustHex("ce69c5713dac3537254e7be59759cf59c15abd530d10501ccf9028a5786314cf08000002298c03ed7d454a101eb7022bc95f7e5f41ac78d0860303c8010080c2d72f0000e7670f32038107a59a2b9cfefae36ea21f5aa63c00"),
			op: &UnsignedOperation{
				Branch: "BMHBtAaUv59LipV1czwZ5iQkxEktPJDE7A9sYXPkPeRzbBasNY8",
				Contents: []OperationContents{
					&OpTransaction{
						Manager: Manager{
							Source:       "tz1KqTpEZ7Yob7QbPE4Hy4Wo8fHG8LhKxZSx",
							Fee:          big.NewInt(50000),
							Counter:      big.NewInt(3),
							GasLimit:     big.NewInt(200),
							StorageLimit: big.NewInt(0),
						},
						Amount:      big.NewInt(100000000),
						Destination: "tz1gjaF81ZRRvdzjobyfVNsAeSC6PScjfQwN",
					},
				},
			},
		},
		{
			data: mustHex("ce69c5713dac3537254e7be59759cf59c15abd530d10501ccf9028a5786314cf6c0002298c03ed7d454a101eb7022bc95f7e5f41ac78d0860303c8010080c2d72f0000e7670f32038107a59a2b9cfefae36ea21f5aa63c006b00f9b3d4be657854c737e8695a757140be34246af9f50994dd7c904e0000c64ae25c006340b984441995d910fdfbce7d332327ee145f08ef03119d4828176e00ad271c36556ecbcb3d6c1ce77ffe1a8155fc4f608c0b02904e00ff00707889a622339b5cf0447d87e5f9f93f2a387251"),
			op: &UnsignedOperation{
				Branch: "BMHBtAaUv59LipV1czwZ5iQkxEktPJDE7A9sYXPkPeRzbBasNY8",
				Contents: []OperationContents{
					&OpTransaction{
						Manager: Manager{
							Source:       "tz1KqTpEZ7Yob7QbPE4Hy4Wo8fHG8LhKxZSx",
							Fee:          big.NewInt(50000),
							Counter:      big.NewInt(3),
							GasLimit:     big.NewInt(200),
							StorageLimit: big.NewInt(0),
						},
						Amount:      big.NewInt(100000000),
						Destination: "tz1gjaF81ZRRvdzjobyfVNsAeSC6PScjfQwN",
					},
					&OpReveal{
						Manager: Manager{
							Source:       "tz1iQLNmGLdFF3sApRjKhrahXAJBTdG3goGc",
							Fee:          big.NewInt(1269),
							Counter:      big.NewInt(2043540),
							GasLimit:     big.NewInt(10000),
							StorageLimit: big.NewInt(0),
						},
						PublicKey: "edpkv9Z42q8rLARYHtEW4WM8cgyGcF8PDvdHRBcNweEzFUovR5bbbL",
					},
					&OpDelegation{
						Manager: Manager{
							Source:       "tz1bRaSjKZrSrSeQHBDiCqjKXqtZYZM1t8FW",
							Fee:          big.NewInt(1420),
							Counter:      big.NewInt(2),
							GasLimit:     big.NewInt(10000),
							StorageLimit: big.NewInt(0),
						},
						Delegate: "tz1Vtimi84kLh9RANfRVX2JvYtP4NPCT1aFm",
					},
				},
			},
		},
		{
			data: mustHex("8ab9fab6bc7a3c8f9e0930b293faa506fb641abad6b979e9e16a632e229a9e550000098d4b"),
			op: &UnsignedOperation{
				Branch: "BLmNvANeVQhNoNCkXN45XdstCjpaXv4TDWJTraAALCcQ75ioeMj",
				Contents: []OperationContents{
					&OpEndorsement{
						Level: 625995,
					},
				},
			},
		},
		{
			data: mustHex("ca5e93ad04d116af3295e879a0add96611db0f541f27a194b8e5b0e0c8bd92486d005f450441f41ee11eee78a31d1e1e55627c783bd6ef0acc018157c30280c2d72f000000001c02000000170500036805010368050202000000080316053d036d03420000000a010000000568656c6c6f"),
			op: &UnsignedOperation{
				Branch: "BMFQbFcKBYSv5FpKiMjS46LdCcjJMhnizJpqoaWFHDj3jDYAxvj",
				Contents: []OperationContents{
					&OpOrigination{
						Manager: Manager{
							Source:       "tz1UKmZhi8dhUX5a5QTfCrsH9pK4dt1dVfJo",
							Fee:          big.NewInt(1391),
							Counter:      big.NewInt(204),
							GasLimit:     big.NewInt(11137),
							StorageLimit: big.NewInt(323),
						},
						Balance: big.NewInt(100000000),
						Script: &ScriptedContracts{
							Code:    mustHex("02000000170500036805010368050202000000080316053d036d0342"),
							Storage: mustHex("010000000568656c6c6f"),
						},
					},
				},
			},
		},
		{
			data: mustHex("1dc1a5b193d1bf8ad500c26209ebdc75f0e71e906de9b7cb45b91f9880037842047d663b831a15c9a3e2d85b141a229486ead3a485fa143cb83c5607f7a1d54dca308073ced76c58a9"),
			op: &UnsignedOperation{
				Branch: "BKwPRXtN67dPwkjoXu2q3E7fVCV9xfyN5vckGqxdAGppTBL445Z",
				Contents: []OperationContents{
					&OpActivateAccount{
						PublicKeyHash: "tz1X55dLMTVKA1knjV15zNiQ3cJoJqrYKkRM",
						Secret:        mustHex("fa143cb83c5607f7a1d54dca308073ced76c58a9"),
					},
				},
			},
		},
		{
			data: mustHex("12758196431d8beaa7e644993007477150da3355d363c8266ced8951404711db03000000ce00108f94061536a898fa5b5f71f33303e6c81c5b974fb7acb81fb969eb3e8d2d019446932d000000005f37de3c04e9c17220fde68b1c5cca2ad49ab6bbfd91c665a4687d223bacf1c93975503c22000000110000000101000000080000000000068f943745c4cde8b4437f5a13703497a8f27f27dcd07a00212b8226060e1f95fa62680000ba45727c8e3d040000158204f817c93ff4e500a877b89935d7769690c19f4155cca5f0c7b838d1a18fdc5fa452903ba5a5fbcf5fe391a55c192a31ee22d82c1ba59af0f9304f52470c000000ce00108f94061536a898fa5b5f71f33303e6c81c5b974fb7acb81fb969eb3e8d2d019446932d000000005f37de3c0461d368abdc29209a178f37b8af74fc2740c0380678644a65bb057452055b7664000000110000000101000000080000000000068f943745c4cde8b4437f5a13703497a8f27f27dcd07a00212b8226060e1f95fa62680000ba45727cfecf070000881c83aa3283505caa813d738206d9e47313837c04bf3ce69a3eed452355c34f1e2d523eb07e53588e6e2cf0567400bc8c153e61dae3ab94876b75497b88c706"),
			op: &UnsignedOperation{
				Branch: "BKrQr2tzLfwpu77h7wb8vJmAiZrD7vhBKHj3WJBnH2Wcj1Gwoqe",
				Contents: []OperationContents{
					&OpDoubleBakingEvidence{
						BlockHeader1: &BlockHeader{
							Level:          1085332,
							Proto:          6,
							Predecessor:    "BKsdCv5tsbZ8bYYW5pfkhxDrusgGrEbCczH7GetyofAZPPRgnjn",
							Timestamp:      mustTime("2020-08-15T13:08:12Z"),
							ValidationPass: 4,
							OperationsHash: "LLob6ezDsDXTAN2ew6VDEzmz5NpMfi3wdiYjPesWV6FgkcRtEqXZT",
							Fitness: [][]uint8{
								{0x01},
								{0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x8f, 0x94},
							},
							Context:          "CoV4eieX2wbaeDRK6yNZ3vnC329nDZjWKon48GAHVW2yu49wckYR",
							Priority:         0,
							ProofOfWorkNonce: []uint8{0xba, 0x45, 0x72, 0x7c, 0x8e, 0x3d, 0x04, 0x00},
							Signature:        "sigQoVq2enb3a9QuT16K7eYgAQ8GLVkPHm6H3ziaqvvP3njRX38LcZS76cS5TQ3xXmuePZupcPxkpXUbFb72jn8ePCxFZqV8",
						},
						BlockHeader2: &BlockHeader{
							Level:          1085332,
							Proto:          6,
							Predecessor:    "BKsdCv5tsbZ8bYYW5pfkhxDrusgGrEbCczH7GetyofAZPPRgnjn",
							Timestamp:      mustTime("2020-08-15T13:08:12Z"),
							ValidationPass: 4,
							OperationsHash: "LLoa4nqohFX77Mkhj89SriZtRGQFkagaZC7AdGHjkhifMmdEhM7gL",
							Fitness: [][]uint8{
								{0x01},
								{0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x8f, 0x94},
							},
							Context:          "CoV4eieX2wbaeDRK6yNZ3vnC329nDZjWKon48GAHVW2yu49wckYR",
							Priority:         0,
							ProofOfWorkNonce: []uint8{0xba, 0x45, 0x72, 0x7c, 0xfe, 0xcf, 0x07, 0x00},
							Signature:        "sigfo7dKzzFdS1x5Ygbf8RBqt32zckgQ2qV9SEhEnSWg7KEH16dMr2dTiz9EjUUVckZeMiZoeaTFF1r1DQk1F93wiwM3VC3e",
						},
					},
				},
			},
		},
		{
			data: mustHex("8bec704d3e1c4a027e07f2f8f7d009cce48338e715fb819d3c8724a6a50d24f40200000065a60703a9567bf69ec66b368c3d8562eba4cbf29278c2c10447a684e3aa143685000008773bd3a9e1467b32104921d4e2dd93265739c1a5faee7a7f8880842b096c0b6714200c43fd5872f82581dfe1cb3a76ccdadaa4d6361d72b4abee6884cb7ed87f0b04000000656280d069cca0c2c8c97c172cc0530e3861cf8050d80970866a388c19bcbbf15f000008773b0ef3e51b218d04c29211b89f5b7582a7169b4810e6dbe46732b44c84331ae6cb32ced7c53ef55e7a2358ed66dedcb98daff1d8ec4f0638f74f215083526d2e03"),
			op: &UnsignedOperation{
				Branch: "BLmuViQ4BUbLcuku4pXHxZz8YbecVSD5e2srQtMWFdVy2e8bgPL",
				Contents: []OperationContents{
					&OpDoubleEndorsementEvidence{
						Op1: &InlinedEndorsement{
							OpEndorsement: OpEndorsement{
								Level: 554811,
							},
							Branch:    "BLyQHMFeNzZEKHmKgfD9imcowLm8hc4aUo16QtYZcS5yvx7RFqQ",
							Signature: "sigqgQgW5qQCsuHP5HhMhAYR2HjcChUE7zAczsyCdF681rfZXpxnXFHu3E6ycmz4pQahjvu3VLfa7FMCxZXmiMiuZFQS4MHy",
						},
						Op2: &InlinedEndorsement{
							OpEndorsement: OpEndorsement{
								Level: 554811,
							},
							Branch:    "BLTfU3iAfPFMuHTmC1F122AHqdhqnFTfkxBmzYCWtCkBMpYNjxw",
							Signature: "sigPwkrKhsDdEidvvUgEEtsaVhyiGmzhCYqCJGKqbYMtH8KxkrFds2HmpDCpRxSTnehKoSC8XKCs9eej6PEzcZoy6fqRAPEZ",
						},
					},
				},
			},
		},
	}
	as := assert.New(t)

	for _, tst := range cases {
		buf := tst.data
		op, err := parseUnsignedOperation(&buf)
		if !as.NoError(err) {
			continue
		}
		as.Empty(buf)
		as.Equal(tst.op, op)
	}
}

func TestParseUnsignedMessage(t *testing.T) {
	type testCase struct {
		data []byte
		msg  UnsignedMessage
	}

	var cases = []testCase{
		{
			data: mustHex("029caecab9c1f5142a0e842be39063c79c6d8952fd74f7957e1d471ffe14bb45c0faa130200000058213"),
			msg: &UnsignedEndorsement{
				ChainID: "NetXjD3HPJJjmcd",
				Branch:  "BMBhiTEp4X5mqqHJPFUK87GoV3ojoABGyqgDSQnUhJtVtwa3zdi",
				OpEndorsement: OpEndorsement{
					Level: 360979,
				},
			},
		},
		{
			data: mustHex("039146a3769e88e5af02f4789dfb23090c7b601d26a81c4cd114c26cfc42050ce8050010f65c7e592ac9e222ca88d959d6dc1020885390000000210000002040cab83d3f37a64da26b57ad3d0432ae881293a25169ada387bfc74a1cbf9e6e"),
			msg: &UnsignedOperation{
				Branch: "BLpGDPAutvEr8MNBm8nzpMLSY5F1tb5MEX9x5sQ6LqtR5TgnmFz",
				Contents: []OperationContents{
					&OpProposals{
						Source:    "tz1MBidfvWhJ64MuJapKExcP5SV4HQWyiJwS",
						Period:    33,
						Proposals: []string{"PsDELPH1Kxsxt8f9eWbxQeRxkjfbxoqM52jvs5Y5fBxWWh4ifpo"},
					},
				},
			},
		},
	}
	as := assert.New(t)

	for _, tst := range cases {
		buf := tst.data
		msg, err := parseUnsignedMessage(&buf)
		if !as.NoError(err) {
			continue
		}
		as.Empty(buf)
		as.Equal(tst.msg, msg)
	}
}

func mustTime(s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		panic(err)
	}
	return t
}

func TestBlockHeader(t *testing.T) {
	type testCase struct {
		data  []byte
		block *BlockHeader
	}

	var cases = []testCase{
		{
			data: mustHex("00033816011dc1a5b193d1bf8ad500c26209ebdc75f0e71e906de9b7cb45b91f9880037842000000005d8e4e8104a3e226c7b4a8700c985e470581dfdd13067e808d8b163fe838c42abda7f478e50000001100000001010000000800000000000338152851a65d186d0cfa747b890ca9086aa0feef05b573aa82c3a32fba55e1c5f99f04d2112233445566778800"),
			block: &BlockHeader{
				Level:          210966,
				Proto:          1,
				Predecessor:    "BKwPRXtN67dPwkjoXu2q3E7fVCV9xfyN5vckGqxdAGppTBL445Z",
				Timestamp:      mustTime("2019-09-27T18:01:37Z"),
				ValidationPass: 4,
				OperationsHash: "LLoaZtCFHbHQoi797K93Gug9jwWP52iGoixzWBDTqEL717mvYBAAX",
				Fitness: [][]uint8{
					{0x01},
					{0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x38, 0x15},
				},
				Context:          "CoUx4kRYc9xWSXFLAk3ukiJ3n7MLMVt3Pb3xH4WYqZiUZaiwd4JT",
				Priority:         1234,
				ProofOfWorkNonce: []uint8{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88},
			},
		},
	}

	as := assert.New(t)

	for _, tst := range cases {
		buf := tst.data
		b, err := parseBlockHeader(&buf, false)
		if !as.NoError(err) {
			continue
		}
		as.Empty(buf)
		as.Equal(tst.block, b)
	}
}
