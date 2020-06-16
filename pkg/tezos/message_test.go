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
		op   *UnsignedEndorsement
	}

	var cases = []testCase{
		{

			data: mustHex("029caecab9c1f5142a0e842be39063c79c6d8952fd74f7957e1d471ffe14bb45c0faa130200000058213"),
			op: &UnsignedEndorsement{
				ChainID: "NetXjD3HPJJjmcd",
				OpEndorsement: OpEndorsement{
					Level: 360979,
				},
			},
		},
	}
	as := assert.New(t)

	for _, tst := range cases {
		buf := tst.data
		op, err := ParseUnsignedMessage(buf)
		if !as.NoError(err) {
			continue
		}
		as.Equal(tst.op, op)
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
					[]uint8{0x01},
					[]uint8{0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x38, 0x15},
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
		b, err := parseBlockHeader(&buf)
		if !as.NoError(err) {
			continue
		}
		as.Empty(buf)
		as.Equal(tst.block, b)
	}
}
