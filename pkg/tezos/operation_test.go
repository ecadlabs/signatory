package tezos

import (
	"encoding/hex"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type opTestCase struct {
	Kind      string
	Data      string
	Operation Operation
}

func strTime(s string) time.Time {
	t, err := time.Parse("2006-01-02 15:04:05 -0700 MST", s)
	if err != nil {
		panic(err)
	}
	return time.Unix(t.Unix(), 0).UTC()
}

// tezos/tezt/_regressions/encoding/hangzhou.operation.out
// tezos/tezt/_regressions/encoding/ithaca.operation.out
var testData = map[string][]opTestCase{
	"hangzhou": {
		{
			Kind: "activate_account",
			Data: "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a804c55cf02dbeecc978d9c84625dcae72bb77ea4fbd41f98b15efc63fa893d61d7d6eee4a2ce9427ac466804fe735e06e97e26da8236b6341b91c625d5e82b3524ec0a88cc982365e70f8a5b9bc65df2ea6d21ee244cc3a96fb33031c394c78b1179ff1b8a44237740c",
			Operation: &OpActivateAccount{
				PublicKeyHash: "tz1ddb9NMYHZi5UzPdzTZMYQQZoMub195zgv",
				Secret:        []uint8{0x41, 0xf9, 0x8b, 0x15, 0xef, 0xc6, 0x3f, 0xa8, 0x93, 0xd6, 0x1d, 0x7d, 0x6e, 0xee, 0x4a, 0x2c, 0xe9, 0x42, 0x7a, 0xc4},
			},
		},
		{
			Kind: "ballot",
			Data: "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8060002298c03ed7d454a101eb7022bc95f7e5f41ac78000002cf7663cf120f3dc8189d5dc7d4d7a0483bcc53f3f18e700f5a2f5076aa8b9dc55c0066804fe735e06e97e26da8236b6341b91c625d5e82b3524ec0a88cc982365e70f8a5b9bc65df2ea6d21ee244cc3a96fb33031c394c78b1179ff1b8a44237740c",
			Operation: &OpBallot{
				Source:   "tz1KqTpEZ7Yob7QbPE4Hy4Wo8fHG8LhKxZSx",
				Period:   719,
				Proposal: "PscqRYywd243M2eZspXZEJGsRmNchp4ZKfKmoyEZTRHeLQvVGjp",
				Ballot:   "yay",
			},
		},
		{
			Kind: "delegation",
			Data: "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a86e0002298c03ed7d454a101eb7022bc95f7e5f41ac7821dc05edecc004adcacdb7d4010066804fe735e06e97e26da8236b6341b91c625d5e82b3524ec0a88cc982365e70f8a5b9bc65df2ea6d21ee244cc3a96fb33031c394c78b1179ff1b8a44237740c",
			Operation: &OpDelegation{
				Manager: Manager{
					Source:       "tz1KqTpEZ7Yob7QbPE4Hy4Wo8fHG8LhKxZSx",
					Fee:          big.NewInt(33),
					Counter:      big.NewInt(732),
					GasLimit:     big.NewInt(9451117),
					StorageLimit: big.NewInt(57024931117),
				},
			},
		},
		{
			Kind: "double_baking_evidence",
			Data: "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a803000000cf00000533010e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8000000005e9dcbb00442e9bc4583d4f9fa6ba422733f45d3a44397141a953d2237bf8df62e5046eef700000011000000010100000008000000000000000a4c7319284b55068bb7c4e0b9f8585729db7fb27ab4ca9cff2038a1fc324f650c0000101895ca00000000000066804fe735e06e97e26da8236b6341b91c625d5e82b3524ec0a88cc982365e70f8a5b9bc65df2ea6d21ee244cc3a96fb33031c394c78b1179ff1b8a44237740c000000cf00000533010e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8000000005e9dcbb00442e9bc4583d4f9fa6ba422733f45d3a44397141a953d2237bf8df62e5046eef700000011000000010100000008000000000000000a4c7319284b55068bb7c4e0b9f8585729db7fb27ab4ca9cff2038a1fc324f650c0000101895ca00000000000066804fe735e06e97e26da8236b6341b91c625d5e82b3524ec0a88cc982365e70f8a5b9bc65df2ea6d21ee244cc3a96fb33031c394c78b1179ff1b8a44237740c66804fe735e06e97e26da8236b6341b91c625d5e82b3524ec0a88cc982365e70f8a5b9bc65df2ea6d21ee244cc3a96fb33031c394c78b1179ff1b8a44237740c",
			Operation: &OpDoubleBakingEvidence{
				BlockHeader1: &ShellBlockHeader{
					Level:          1331,
					Proto:          1,
					Predecessor:    "BKpbfCvh777DQHnXjU2sqHvVUNZ7dBAdqEfKkdw8EGSkD9LSYXb",
					Timestamp:      strTime("2020-04-20 16:20:00 +0000 UTC"),
					ValidationPass: 4,
					OperationsHash: "LLoZqBDX1E2ADRXbmwYo8VtMNeHG6Ygzmm4Zqv97i91UPBQHy9Vq3",
					Fitness: [][]uint8{
						{
							0x01,
						},
						{
							0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a,
						},
					},
					Context: "CoVDyf9y9gHfAkPWofBJffo4X4bWjmehH2LeVonDcCKKzyQYwqdk",
				},
				BlockHeader2: &ShellBlockHeader{
					Level:          1331,
					Proto:          1,
					Predecessor:    "BKpbfCvh777DQHnXjU2sqHvVUNZ7dBAdqEfKkdw8EGSkD9LSYXb",
					Timestamp:      strTime("2020-04-20 16:20:00 +0000 UTC"),
					ValidationPass: 4,
					OperationsHash: "LLoZqBDX1E2ADRXbmwYo8VtMNeHG6Ygzmm4Zqv97i91UPBQHy9Vq3",
					Fitness: [][]uint8{
						{
							0x01,
						},
						{
							0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a,
						},
					},
					Context: "CoVDyf9y9gHfAkPWofBJffo4X4bWjmehH2LeVonDcCKKzyQYwqdk",
				},
			},
		},
		{
			Kind: "double_endorsement_evidence",
			Data: "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a802000000650e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8000000053366804fe735e06e97e26da8236b6341b91c625d5e82b3524ec0a88cc982365e70f8a5b9bc65df2ea6d21ee244cc3a96fb33031c394c78b1179ff1b8a44237740c000000650e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8000000053366804fe735e06e97e26da8236b6341b91c625d5e82b3524ec0a88cc982365e70f8a5b9bc65df2ea6d21ee244cc3a96fb33031c394c78b1179ff1b8a44237740c000066804fe735e06e97e26da8236b6341b91c625d5e82b3524ec0a88cc982365e70f8a5b9bc65df2ea6d21ee244cc3a96fb33031c394c78b1179ff1b8a44237740c",
			Operation: &OpDoubleEndorsementEvidence{
				Op1: &InlinedEndorsement{
					Endorsement: &OpEmmyEndorsement{
						Level: 1331,
					},
					Branch:    "BKpbfCvh777DQHnXjU2sqHvVUNZ7dBAdqEfKkdw8EGSkD9LSYXb",
					Signature: "sigbQ5ZNvkjvGssJgoAnUAfY4Wvvg3QZqawBYB1j1VDBNTMBAALnCzRHWzer34bnfmzgHg3EvwdzQKdxgSghB897cono6gbQ",
				},
				Op2: &InlinedEndorsement{
					Endorsement: &OpEmmyEndorsement{
						Level: 1331,
					},
					Branch:    "BKpbfCvh777DQHnXjU2sqHvVUNZ7dBAdqEfKkdw8EGSkD9LSYXb",
					Signature: "sigbQ5ZNvkjvGssJgoAnUAfY4Wvvg3QZqawBYB1j1VDBNTMBAALnCzRHWzer34bnfmzgHg3EvwdzQKdxgSghB897cono6gbQ",
				},
			},
		},
		{
			Kind: "endorsement_with_slot",
			Data: "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a80a000000650e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8000000053366804fe735e06e97e26da8236b6341b91c625d5e82b3524ec0a88cc982365e70f8a5b9bc65df2ea6d21ee244cc3a96fb33031c394c78b1179ff1b8a44237740c000066804fe735e06e97e26da8236b6341b91c625d5e82b3524ec0a88cc982365e70f8a5b9bc65df2ea6d21ee244cc3a96fb33031c394c78b1179ff1b8a44237740c",
			Operation: &OpEndorsementWithSlot{
				InlinedEndorsement: InlinedEndorsement{
					Endorsement: &OpEmmyEndorsement{
						Level: 1331,
					},
					Branch:    "BKpbfCvh777DQHnXjU2sqHvVUNZ7dBAdqEfKkdw8EGSkD9LSYXb",
					Signature: "sigbQ5ZNvkjvGssJgoAnUAfY4Wvvg3QZqawBYB1j1VDBNTMBAALnCzRHWzer34bnfmzgHg3EvwdzQKdxgSghB897cono6gbQ",
				},
				Slot: 0,
			},
		},
		{
			Kind: "endorsement",
			Data: "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8000000053366804fe735e06e97e26da8236b6341b91c625d5e82b3524ec0a88cc982365e70f8a5b9bc65df2ea6d21ee244cc3a96fb33031c394c78b1179ff1b8a44237740c",
			Operation: &OpEmmyEndorsement{
				Level: 1331,
			},
		},
		{
			Kind: "origination",
			Data: "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a86d0002298c03ed7d454a101eb7022bc95f7e5f41ac7821dc05edecc004adcacdb7d401af9105ff0002298c03ed7d454a101eb7022bc95f7e5f41ac7800000020020000001b050003680501056303680502020000000a03160346053d036d03420000000e020000000901000000047465737466804fe735e06e97e26da8236b6341b91c625d5e82b3524ec0a88cc982365e70f8a5b9bc65df2ea6d21ee244cc3a96fb33031c394c78b1179ff1b8a44237740c",
			Operation: &OpOrigination{
				Manager: Manager{
					Source:       "tz1KqTpEZ7Yob7QbPE4Hy4Wo8fHG8LhKxZSx",
					Fee:          big.NewInt(33),
					Counter:      big.NewInt(732),
					GasLimit:     big.NewInt(9451117),
					StorageLimit: big.NewInt(57024931117),
				},
				Balance:  big.NewInt(84143),
				Delegate: "tz1KqTpEZ7Yob7QbPE4Hy4Wo8fHG8LhKxZSx",
				Script: &ScriptedContract{
					Code: []uint8{
						0x02, 0x00, 0x00, 0x00, 0x1b, 0x05, 0x00, 0x03, 0x68, 0x05, 0x01, 0x05, 0x63, 0x03, 0x68, 0x05,
						0x02, 0x02, 0x00, 0x00, 0x00, 0x0a, 0x03, 0x16, 0x03, 0x46, 0x05, 0x3d, 0x03, 0x6d, 0x03, 0x42,
					},
					Storage: []uint8{
						0x02, 0x00, 0x00, 0x00, 0x09, 0x01, 0x00, 0x00, 0x00, 0x04, 0x74, 0x65, 0x73, 0x74,
					},
				},
			},
		},
		{
			Kind: "proposals",
			Data: "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8050002298c03ed7d454a101eb7022bc95f7e5f41ac78000002cf000000407663cf120f3dc8189d5dc7d4d7a0483bcc53f3f18e700f5a2f5076aa8b9dc55c7663cf120f3dc8189d5dc7d4d7a0483bcc53f3f18e700f5a2f5076aa8b9dc55c66804fe735e06e97e26da8236b6341b91c625d5e82b3524ec0a88cc982365e70f8a5b9bc65df2ea6d21ee244cc3a96fb33031c394c78b1179ff1b8a44237740c",
			Operation: &OpProposals{
				Source: "tz1KqTpEZ7Yob7QbPE4Hy4Wo8fHG8LhKxZSx",
				Period: 719,
				Proposals: []string{
					"PscqRYywd243M2eZspXZEJGsRmNchp4ZKfKmoyEZTRHeLQvVGjp",
					"PscqRYywd243M2eZspXZEJGsRmNchp4ZKfKmoyEZTRHeLQvVGjp",
				},
			},
		},
		{
			Kind: "reveal",
			Data: "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a86b0002298c03ed7d454a101eb7022bc95f7e5f41ac7821dc05edecc004adcacdb7d401004798d2cc98473d7e250c898885718afd2e4efbcb1a1595ab9730761ed830de0f66804fe735e06e97e26da8236b6341b91c625d5e82b3524ec0a88cc982365e70f8a5b9bc65df2ea6d21ee244cc3a96fb33031c394c78b1179ff1b8a44237740c",
			Operation: &OpReveal{
				Manager: Manager{
					Source:       "tz1KqTpEZ7Yob7QbPE4Hy4Wo8fHG8LhKxZSx",
					Fee:          big.NewInt(33),
					Counter:      big.NewInt(732),
					GasLimit:     big.NewInt(9451117),
					StorageLimit: big.NewInt(57024931117),
				},
				PublicKey: "edpkuBknW28nW72KG6RoHtYW7p12T6GKc7nAbwYX5m8Wd9sDVC9yav",
			},
		},
		{
			Kind: "seed_nonce_revelation",
			Data: "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a80100000533000000000000000000000000000000000000000000000000000000000000000066804fe735e06e97e26da8236b6341b91c625d5e82b3524ec0a88cc982365e70f8a5b9bc65df2ea6d21ee244cc3a96fb33031c394c78b1179ff1b8a44237740c",
			Operation: &OpSeedNonceRevelation{
				Level: 1331,
				Nonce: make([]uint8, 32),
			},
		},
		{
			Kind: "transaction",
			Data: "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a86c0002298c03ed7d454a101eb7022bc95f7e5f41ac7821dc05edecc004adcacdb7d40197030138560805b4c8d7b7fbbafad5c59dbfa3878ca70500ffff06616374696f6e000000070200000002034f66804fe735e06e97e26da8236b6341b91c625d5e82b3524ec0a88cc982365e70f8a5b9bc65df2ea6d21ee244cc3a96fb33031c394c78b1179ff1b8a44237740c",
			Operation: &OpTransaction{
				Manager: Manager{
					Source:       "tz1KqTpEZ7Yob7QbPE4Hy4Wo8fHG8LhKxZSx",
					Fee:          big.NewInt(33),
					Counter:      big.NewInt(732),
					GasLimit:     big.NewInt(9451117),
					StorageLimit: big.NewInt(57024931117),
				},
				Amount:      big.NewInt(407),
				Destination: "KT1DieU51jzXLerQx5AqMCiLC1SsCeM8yRat",
				Parameters: &TxParameters{
					Value: []uint8{
						0x02, 0x00, 0x00, 0x00, 0x02, 0x03, 0x4f,
					},
					Entrypoint: "action",
				},
			},
		},
	},
	"ithaca": {
		{
			Kind: "activate_account",
			Data: "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a804c55cf02dbeecc978d9c84625dcae72bb77ea4fbd41f98b15efc63fa893d61d7d6eee4a2ce9427ac466804fe735e06e97e26da8236b6341b91c625d5e82b3524ec0a88cc982365e70f8a5b9bc65df2ea6d21ee244cc3a96fb33031c394c78b1179ff1b8a44237740c",
			Operation: &OpActivateAccount{
				PublicKeyHash: "tz1ddb9NMYHZi5UzPdzTZMYQQZoMub195zgv",
				Secret: []uint8{
					0x41, 0xf9, 0x8b, 0x15, 0xef, 0xc6, 0x3f, 0xa8, 0x93, 0xd6, 0x1d, 0x7d, 0x6e, 0xee, 0x4a, 0x2c,
					0xe9, 0x42, 0x7a, 0xc4,
				},
			},
		},
		{
			Kind: "ballot",
			Data: "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8060002298c03ed7d454a101eb7022bc95f7e5f41ac78000002cf7663cf120f3dc8189d5dc7d4d7a0483bcc53f3f18e700f5a2f5076aa8b9dc55c0066804fe735e06e97e26da8236b6341b91c625d5e82b3524ec0a88cc982365e70f8a5b9bc65df2ea6d21ee244cc3a96fb33031c394c78b1179ff1b8a44237740c",
			Operation: &OpBallot{
				Source:   "tz1KqTpEZ7Yob7QbPE4Hy4Wo8fHG8LhKxZSx",
				Period:   719,
				Proposal: "PscqRYywd243M2eZspXZEJGsRmNchp4ZKfKmoyEZTRHeLQvVGjp",
				Ballot:   "yay",
			},
		},
		{
			Kind: "delegation",
			Data: "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a86e0002298c03ed7d454a101eb7022bc95f7e5f41ac7821dc05edecc004adcacdb7d401ff0002298c03ed7d454a101eb7022bc95f7e5f41ac7866804fe735e06e97e26da8236b6341b91c625d5e82b3524ec0a88cc982365e70f8a5b9bc65df2ea6d21ee244cc3a96fb33031c394c78b1179ff1b8a44237740c",
			Operation: &OpDelegation{
				Manager: Manager{
					Source:       "tz1KqTpEZ7Yob7QbPE4Hy4Wo8fHG8LhKxZSx",
					Fee:          big.NewInt(33),
					Counter:      big.NewInt(732),
					GasLimit:     big.NewInt(9451117),
					StorageLimit: big.NewInt(57024931117),
				},
				Delegate: "tz1KqTpEZ7Yob7QbPE4Hy4Wo8fHG8LhKxZSx",
			},
		},
		{
			Kind: "double_baking_evidence",
			Data: "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a803000000f100000533010e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8000000005e9dcbb00442e9bc4583d4f9fa6ba422733f45d3a44397141a953d2237bf8df62e5046eef700000011000000010100000008000000000000000a4c7319284b55068bb7c4e0b9f8585729db7fb27ab4ca9cff2038a1fc324f650c000000000000000000000000000000000000000000000000000000000000000000000000101895ca00000000000066804fe735e06e97e26da8236b6341b91c625d5e82b3524ec0a88cc982365e70f8a5b9bc65df2ea6d21ee244cc3a96fb33031c394c78b1179ff1b8a44237740c000000f100000533010e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8000000005e9dcbb00442e9bc4583d4f9fa6ba422733f45d3a44397141a953d2237bf8df62e5046eef700000011000000010100000008000000000000000a4c7319284b55068bb7c4e0b9f8585729db7fb27ab4ca9cff2038a1fc324f650c000000000000000000000000000000000000000000000000000000000000000000000000101895ca00000000000066804fe735e06e97e26da8236b6341b91c625d5e82b3524ec0a88cc982365e70f8a5b9bc65df2ea6d21ee244cc3a96fb33031c394c78b1179ff1b8a44237740c66804fe735e06e97e26da8236b6341b91c625d5e82b3524ec0a88cc982365e70f8a5b9bc65df2ea6d21ee244cc3a96fb33031c394c78b1179ff1b8a44237740c",
			Operation: &OpDoubleBakingEvidence{
				BlockHeader1: &ShellBlockHeader{
					Level:          1331,
					Proto:          1,
					Predecessor:    "BKpbfCvh777DQHnXjU2sqHvVUNZ7dBAdqEfKkdw8EGSkD9LSYXb",
					Timestamp:      strTime("2020-04-20 16:20:00 +0000 UTC"),
					ValidationPass: 4,
					OperationsHash: "LLoZqBDX1E2ADRXbmwYo8VtMNeHG6Ygzmm4Zqv97i91UPBQHy9Vq3",
					Fitness: [][]uint8{
						{
							0x01,
						},
						{
							0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a,
						},
					},
					Context: "CoVDyf9y9gHfAkPWofBJffo4X4bWjmehH2LeVonDcCKKzyQYwqdk",
				},
				BlockHeader2: &ShellBlockHeader{
					Level:          1331,
					Proto:          1,
					Predecessor:    "BKpbfCvh777DQHnXjU2sqHvVUNZ7dBAdqEfKkdw8EGSkD9LSYXb",
					Timestamp:      strTime("2020-04-20 16:20:00 +0000 UTC"),
					ValidationPass: 4,
					OperationsHash: "LLoZqBDX1E2ADRXbmwYo8VtMNeHG6Ygzmm4Zqv97i91UPBQHy9Vq3",
					Fitness: [][]uint8{
						{
							0x01,
						},
						{
							0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a,
						},
					},
					Context: "CoVDyf9y9gHfAkPWofBJffo4X4bWjmehH2LeVonDcCKKzyQYwqdk",
				},
			},
		},
		{
			Kind: "double_endorsement_evidence",
			Data: "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8020000008b0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a81500000000053300000000000000000000000000000000000000000000000000000000000000000000000066804fe735e06e97e26da8236b6341b91c625d5e82b3524ec0a88cc982365e70f8a5b9bc65df2ea6d21ee244cc3a96fb33031c394c78b1179ff1b8a44237740c0000008b0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a81500000000053300000000000000000000000000000000000000000000000000000000000000000000000066804fe735e06e97e26da8236b6341b91c625d5e82b3524ec0a88cc982365e70f8a5b9bc65df2ea6d21ee244cc3a96fb33031c394c78b1179ff1b8a44237740c66804fe735e06e97e26da8236b6341b91c625d5e82b3524ec0a88cc982365e70f8a5b9bc65df2ea6d21ee244cc3a96fb33031c394c78b1179ff1b8a44237740c",
			Operation: &OpDoubleEndorsementEvidence{
				Op1: &InlinedEndorsement{
					Endorsement: &OpTenderbakeEndorsement{
						Slot:             0,
						Level:            1331,
						Round:            0,
						BlockPayloadHash: "vh1g87ZG6scSYxKhspAUzprQVuLAyoa5qMBKcUfjgnQGnFb3dJcG",
					},
					Branch:    "BKpbfCvh777DQHnXjU2sqHvVUNZ7dBAdqEfKkdw8EGSkD9LSYXb",
					Signature: "sigbQ5ZNvkjvGssJgoAnUAfY4Wvvg3QZqawBYB1j1VDBNTMBAALnCzRHWzer34bnfmzgHg3EvwdzQKdxgSghB897cono6gbQ",
				},
				Op2: &InlinedEndorsement{
					Endorsement: &OpTenderbakeEndorsement{
						Slot:             0,
						Level:            1331,
						Round:            0,
						BlockPayloadHash: "vh1g87ZG6scSYxKhspAUzprQVuLAyoa5qMBKcUfjgnQGnFb3dJcG",
					},
					Branch:    "BKpbfCvh777DQHnXjU2sqHvVUNZ7dBAdqEfKkdw8EGSkD9LSYXb",
					Signature: "sigbQ5ZNvkjvGssJgoAnUAfY4Wvvg3QZqawBYB1j1VDBNTMBAALnCzRHWzer34bnfmzgHg3EvwdzQKdxgSghB897cono6gbQ",
				},
			},
		},
		{
			Kind: "endorsement",
			Data: "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a81500000000053300000000000000000000000000000000000000000000000000000000000000000000000066804fe735e06e97e26da8236b6341b91c625d5e82b3524ec0a88cc982365e70f8a5b9bc65df2ea6d21ee244cc3a96fb33031c394c78b1179ff1b8a44237740c",
			Operation: &OpTenderbakeEndorsement{
				Slot:             0,
				Level:            1331,
				Round:            0,
				BlockPayloadHash: "vh1g87ZG6scSYxKhspAUzprQVuLAyoa5qMBKcUfjgnQGnFb3dJcG",
			},
		},
		{
			Kind: "origination",
			Data: "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a86d0002298c03ed7d454a101eb7022bc95f7e5f41ac7821dc05edecc004adcacdb7d401af9105ff0002298c03ed7d454a101eb7022bc95f7e5f41ac7800000020020000001b050003680501056303680502020000000a03160346053d036d03420000000e020000000901000000047465737466804fe735e06e97e26da8236b6341b91c625d5e82b3524ec0a88cc982365e70f8a5b9bc65df2ea6d21ee244cc3a96fb33031c394c78b1179ff1b8a44237740c",
			Operation: &OpOrigination{
				Manager: Manager{
					Source:       "tz1KqTpEZ7Yob7QbPE4Hy4Wo8fHG8LhKxZSx",
					Fee:          big.NewInt(33),
					Counter:      big.NewInt(732),
					GasLimit:     big.NewInt(9451117),
					StorageLimit: big.NewInt(57024931117),
				},
				Balance:  big.NewInt(84143),
				Delegate: "tz1KqTpEZ7Yob7QbPE4Hy4Wo8fHG8LhKxZSx",
				Script: &ScriptedContract{
					Code: []uint8{
						0x02, 0x00, 0x00, 0x00, 0x1b, 0x05, 0x00, 0x03, 0x68, 0x05, 0x01, 0x05, 0x63, 0x03, 0x68, 0x05,
						0x02, 0x02, 0x00, 0x00, 0x00, 0x0a, 0x03, 0x16, 0x03, 0x46, 0x05, 0x3d, 0x03, 0x6d, 0x03, 0x42,
					},
					Storage: []uint8{
						0x02, 0x00, 0x00, 0x00, 0x09, 0x01, 0x00, 0x00, 0x00, 0x04, 0x74, 0x65, 0x73, 0x74,
					},
				},
			},
		},
		{
			Kind: "proposals",
			Data: "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8050002298c03ed7d454a101eb7022bc95f7e5f41ac78000002cf000000407663cf120f3dc8189d5dc7d4d7a0483bcc53f3f18e700f5a2f5076aa8b9dc55c7663cf120f3dc8189d5dc7d4d7a0483bcc53f3f18e700f5a2f5076aa8b9dc55c66804fe735e06e97e26da8236b6341b91c625d5e82b3524ec0a88cc982365e70f8a5b9bc65df2ea6d21ee244cc3a96fb33031c394c78b1179ff1b8a44237740c",
			Operation: &OpProposals{
				Source: "tz1KqTpEZ7Yob7QbPE4Hy4Wo8fHG8LhKxZSx",
				Period: 719,
				Proposals: []string{
					"PscqRYywd243M2eZspXZEJGsRmNchp4ZKfKmoyEZTRHeLQvVGjp",
					"PscqRYywd243M2eZspXZEJGsRmNchp4ZKfKmoyEZTRHeLQvVGjp",
				},
			},
		},
		{
			Kind: "reveal",
			Data: "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a86b0002298c03ed7d454a101eb7022bc95f7e5f41ac7821dc05edecc004adcacdb7d401004798d2cc98473d7e250c898885718afd2e4efbcb1a1595ab9730761ed830de0f66804fe735e06e97e26da8236b6341b91c625d5e82b3524ec0a88cc982365e70f8a5b9bc65df2ea6d21ee244cc3a96fb33031c394c78b1179ff1b8a44237740c",
			Operation: &OpReveal{
				Manager: Manager{
					Source:       "tz1KqTpEZ7Yob7QbPE4Hy4Wo8fHG8LhKxZSx",
					Fee:          big.NewInt(33),
					Counter:      big.NewInt(732),
					GasLimit:     big.NewInt(9451117),
					StorageLimit: big.NewInt(57024931117),
				},
				PublicKey: "edpkuBknW28nW72KG6RoHtYW7p12T6GKc7nAbwYX5m8Wd9sDVC9yav",
			},
		},
		{
			Kind: "seed_nonce_revelation",
			Data: "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a80100000533000000000000000000000000000000000000000000000000000000000000000066804fe735e06e97e26da8236b6341b91c625d5e82b3524ec0a88cc982365e70f8a5b9bc65df2ea6d21ee244cc3a96fb33031c394c78b1179ff1b8a44237740c",
			Operation: &OpSeedNonceRevelation{
				Level: 1331,
				Nonce: make([]uint8, 32),
			},
		},
		{
			Kind: "transaction",
			Data: "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a86c0002298c03ed7d454a101eb7022bc95f7e5f41ac7821dc05edecc004adcacdb7d40197030138560805b4c8d7b7fbbafad5c59dbfa3878ca70500ffff06616374696f6e000000070200000002034f66804fe735e06e97e26da8236b6341b91c625d5e82b3524ec0a88cc982365e70f8a5b9bc65df2ea6d21ee244cc3a96fb33031c394c78b1179ff1b8a44237740c",
			Operation: &OpTransaction{
				Manager: Manager{
					Source:       "tz1KqTpEZ7Yob7QbPE4Hy4Wo8fHG8LhKxZSx",
					Fee:          big.NewInt(33),
					Counter:      big.NewInt(732),
					GasLimit:     big.NewInt(9451117),
					StorageLimit: big.NewInt(57024931117),
				},
				Amount:      big.NewInt(407),
				Destination: "KT1DieU51jzXLerQx5AqMCiLC1SsCeM8yRat",
				Parameters: &TxParameters{
					Value: []uint8{
						0x02, 0x00, 0x00, 0x00, 0x02, 0x03, 0x4f,
					},
					Entrypoint: "action",
				},
			},
		},
	},
}

var testDataRaw = map[string][]opTestCase{
	"jakarta": {
		{
			Kind: "endorsement",
			Data: "1519a5002792c30000000015b4d26b90b5a56f1333bb2b8f1fce2f121474c7a1e088235a9a24e2bfda5bdd",
			Operation: &OpTenderbakeEndorsement{
				Slot:             6565,
				Level:            2593475,
				Round:            0,
				BlockPayloadHash: "vh1qgaC4FVGQxyDKPGBN1hyvEyhHVHhX6DGvWRVZMDkC6xwtfg4k",
			},
		},
		{
			Kind: "preendorsement",
			Data: "1419e60027926000000000c02203b1c970f9894c2d555e87e7b12c86e343fc0127c2da846fd8ee6dcc5a4c",
			Operation: &OpPreendorsement{
				Slot:             6630,
				Level:            2593376,
				Round:            0,
				BlockPayloadHash: "vh38jtacsXFG8jWG2fpFnSXS48dG65Z3mY9sFno9Wa7TzHCrNi8f",
			},
		},
		{
			Kind: "double_preendorsement_evidence",
			Data: "070000008b8b87b048db84d61c6d8ceaf13538ccf2bbaf2017fb5d804b77aa58ebe088520d1400000004a2e80000000009a56da0405f15df6064b4d704eb9fe6fdaf885a513ed7ba189eb5321d97386f9734c876e5b4df19fc457c6cb308bcad79ca806ad4950f4e7c3118703ecbdd67c77d63c7040fb923c78ee86300b3040bb3d2c6865e69253c57674161cfe261690000008b8b87b048db84d61c6d8ceaf13538ccf2bbaf2017fb5d804b77aa58ebe088520d1400000004a2e800000000ca774e93ab507f6781b8c0312895cfcbb5f5b7df9c261602c7ec71f9e531ae972e36bcd26702165dec701fe072bd07d0bd776da1e9658d0b62806ce17daa06e593eec7d781f9ab4f6b3e8d8c8531072c6f262187144cf2c97c3aa8710ee2304d",
			Operation: &OpDoublePreendorsementEvidence{
				Op1: &InlinedPreendorsement{
					Branch:    "BLmjSefiB3qgkHAQPixgx9riZo5msEpy1SWxfSJVswdMEGCjvCo",
					Signature: "sighmexH8rPcr6APfCn4GgVMHfqVKwGvpL17DSJTNmfbFfXzBTBH8H4e11KZkmndc5wamfnhuCs56tXi2yQ3biC7fbBcecjd",
					OpPreendorsement: OpPreendorsement{
						Slot:             0,
						Level:            303848,
						Round:            0,
						BlockPayloadHash: "vh1kNWid89YM6smqcUvKhwffEKgVdNQF29jjsrzySZvniKBFqdaf",
					},
				},
				Op2: &InlinedPreendorsement{
					Branch:    "BLmjSefiB3qgkHAQPixgx9riZo5msEpy1SWxfSJVswdMEGCjvCo",
					Signature: "sigU2y5fds9nh2qxyzrLVTwCpqinewfSSMZDZx6jHWrsM8SFM7byFb7KK76R5wa3BBmJVtxQtPXZbq6byPkXh1991Rgmj1oN",
					OpPreendorsement: OpPreendorsement{
						Slot:             0,
						Level:            303848,
						Round:            0,
						BlockPayloadHash: "vh3DHqWXCzYdZLZuofDHRBqm8kRE9GfM9kEEjgJ5jaPo4pGMzoWN",
					},
				},
			},
		},
		{
			Kind: "register_global_constant",
			Data: "6f019965ccdba00e7ae3a73ad513cd315a1a59e57f82e303f9edae05b60a500000000f065f03620000000725633363376639",
			Operation: &OpRegisterGlobalConstant{
				Manager: Manager{
					Source:       "tz2NJKztagrEVYMiQjCfoxqeuJvfWAC1BBXM",
					Fee:          big.NewInt(483),
					Counter:      big.NewInt(11253497),
					GasLimit:     big.NewInt(1334),
					StorageLimit: big.NewInt(80),
				},
				Value: []uint8{0x6, 0x5f, 0x3, 0x62, 0x0, 0x0, 0x0, 0x7, 0x25, 0x63, 0x33, 0x63, 0x37, 0x66, 0x39},
			},
		},
		{
			Kind: "set_deposits_limit",
			Data: "7000a31e81ac3425310e3274a4698a793b2839dc0afac602917ee8070000",
			Operation: &OpSetDepositsLimit{
				Manager: Manager{
					Source:       "tz1aWXP237BLwNHJcCD4b3DutCevhqq2T1Z9",
					Fee:          big.NewInt(326),
					Counter:      big.NewInt(16145),
					GasLimit:     big.NewInt(1000),
					StorageLimit: big.NewInt(0),
				},
			},
		},
		{
			Kind: "tx_rollup_origination",
			Data: "9601b5c8c3bb9caaf90cddbffbc177d75a40483c3cb9be03adce38f10ba01f",
			Operation: &OpTxRollupOrigination{
				Source:       "tz2QtRURd7N88BLSHWCugwz9fmye2VnRPsp6",
				Fee:          big.NewInt(446),
				Counter:      big.NewInt(927533),
				GasLimit:     big.NewInt(1521),
				StorageLimit: big.NewInt(4000),
			},
		},
		{
			Kind: "tx_rollup_submit_batch",
			Data: "97012fe12ea64fb134fcff25faa735c6269026a53293d304adce38b5162877a553870ee6f9424cd1adb1e4ff01f6ad1a1aae00000004626c6f6200",
			Operation: &OpTxRollupSubmitBatch{
				Rollup: Rollup{
					Manager: Manager{
						Source:       "tz2CgQBHe4jpFcV36NBuEusxXC7TdtyDmxg6",
						Fee:          big.NewInt(595),
						Counter:      big.NewInt(927533),
						GasLimit:     big.NewInt(2869),
						StorageLimit: big.NewInt(40),
					},
					Rollup: "txr1YTdi9BktRmybwhgkhRK7WPrutEWVGJT7w",
				},
				Content: []uint8{0x62, 0x6c, 0x6f, 0x62},
			},
		},
		{
			Kind: "tx_rollup_commit",
			Data: "9800114b05ee698efaee5c0a3f835460f4a12e31835cdf059ba210fe1d0051b8326e6fcb811b333bd8948acf58a8e3f2d3d30000000d000000202c44b5a00c26b661b6e914cbbb8233830d19984b6bdc62d17ad1cd02387f229c0174a50978d9e0c56e9b03c771b66ee6564405ec7ea50ec38c5b50701947eccab3d2bf7d3e8b985f1b4d0844923f7b713eb4d891d755396c5359752e21214a995e",
			Operation: &OpTxRollupCommit{
				Rollup: Rollup{
					Manager: Manager{
						Source:       "tz1MDU45gNc9Ko1Q9obcz6hQkKSMiQRib6GZ",
						Fee:          big.NewInt(735),
						Counter:      big.NewInt(266523),
						GasLimit:     big.NewInt(3838),
						StorageLimit: big.NewInt(0),
					},
					Rollup: "txr1V16e1hXyVKndP4aE8cujRfryoHTiHK9fG",
				},
				Level: 13,
				Messages: []string{
					"txmr2F2DVV7dyMEbniraje9mshfteTgQzJ48E6GFaQFaXFypRAQy8R",
				},
				Predecessor:     "txc2SgGaGtLMQi7FLJggWMosMWRzn8srFJFgzXyjoLHfaSAmAvYJw",
				InboxMerkleRoot: "txi37NbBsizTqZMDStbcRwFdJAQn1vq2n79Y8j5dpPxFi9zLR9oCU",
			},
		},
		{
			Kind: "tx_rollup_rejection",
			Data: "9c00114b05ee698efaee5c0a3f835460f4a12e31835c951693a210f15a0051b8326e6fcb811b333bd8948acf58a8e3f2d3d30000000b00000000af01b2530bd9f4d594ee6116286cbb045a972305e38e6365b396f49d153815fbdd15c8974b7fdc50aee4bc3f8195e95075ab0fca5d31927917ede7a408fe70c61cd4a0525b2836eca0e797cdf9ae9b3bf58735fd62a7bf21775d46940ae9bd83a8d501130187e8c631aba41d88a67da49cf5f4db947fdf5a76084f1d4b6c14531f6582b239db26dd0375ca7172cdbecd8b6f080ffa58c748f83cc7a2afce164c1bcc53712ff5a9e50c39fb0172acda0a00000000200000000000000000000000000000000000000000000000000000000000000000971808f601eff6881d1e59d638127e03d6b2d2dc4c399bfb67dc5a99078fb6f80000002000000000000000000000000000000000000000000000000000000000000000006e5e83eed76229a39dcc414c02ec1940d2efab22809314ea9a34e6bb54bef90e11da6d1f761ddf9bdb4c9d6e5303ebd41f61858d0a5647a1a7bfe089bf921be90000002000000000000000000000000000000000000000000000000000000000000000000300036e5e83eed76229a39dcc414c02ec1940d2efab22809314ea9a34e6bb54bef90e11944e724304702f74abc0b5543b3765d263c8263b08f568cfdcea367d2d963d000003c70c0e7d1c242a58c214ad02900584878d2293bfe090e17f158ce696f7e640267dc79ffb6b412ba0f9fd9105231b587c83c637aabbb93f0dcc2b22dbc85035a40e29450c0684619fd775f5e10dad62dbb97c6454db5171d7086f0b0e6ee0b865ea31a5ee7c065183273f006a8e534ce4ee245a6ef3728c9dbd39e5eb95531d78b9ff3cb7cb0803618d67a6a8f3630da16a2801724540a7b534a05ff7e60d3b8c7318e1b5d2c2850c03ffbbecd790ce581cf8292c4ca2803de4199506e6a87b79f38b5a6da2efa6c0c372fa5620e3632a61340de80059b2af6c55e1fc6cc949be0d751a23b0a8e2d3ea82150287e8c631aba41d88a67da49cf5f4db947fdf5a7600baff5f78423676a25d9cd27a412dd932327b9b3e1cc26e754a36410a5efbf7b40905000000010000000200e8568946885a26d4648134d25ff896a52291ccc8d64ce918a6b4557952f72431c004000000000c03b4d48696b6f76607bcecca6ae0500889b95b6713c0c61a425764e9fb4a5b1a28f2a5e6f33a2414789aae9a4fd5e55295086e591d39edd1190f6a99387a7f04fa8205000000000000f85245c79b4cc89d59031d51e88677bb83d91f8cf0fbde69a90e6a470aaf0cc405000000000100905f92c1fa026fb87cb3ef030ccafb50df0bf8b23d564b32c4213fb5849d43bdc03c00000000000000070000003087bdec4b6745183b7ea589128f836e037e92a8e7fbad7818c0e371840b78aca9cceb24d627c59ace2962c9b8016060168115021d4b6c14531f6582b239db26dd0375ca7172cdbe00d4f0efaf93a9e84d8e511dbab2868797335a6458144eb83bb86145b46d352041c004000000010c0841185ac1a69273b23eead6fb67135cc61a21c8069fe2507a40044dbbadf64943beeee9b5da27facefe6c3e3316c8936dddc02df86a3590d371bbe2e2a25adb660c04dcf853ba94fb5aca69bf26e2fdf78f41e4ea2b43b14d4a1e94814aa3bc00e3f22deca7804c8253d4411932c3caf5db4eb1a09c4c1c1957781b5a9db049c52c410c03d46fb9dcabad6cd34a10a1d82d2491e8c9d216040a05db59565a6f8be18f683336a9443cca0fbe0b820d9a6f37eca467b836c7bbc61d8608da05608eec7e7494822104cd8b6f080ffa58c748f83cc7a2afce164c1bcc53712ff5a9e50c39fb0172acda00baff5f78423676a25d9cd27a412dd932327b9b3e1cc26e754a36410a5efbf7b4090500000000000000000080c827e7e7cb4dba9d783d571c99f477fe9f9155c42734323671f46f4d0e3704c002003281090500000000000000010078713ac9edf89521dcbad00ca9e5c33f2658ec223696e3edd1ba2ea4c653d64cc0020028",
			Operation: &OpTxRollupRejection{
				Rollup: Rollup{
					Manager: Manager{
						Source:       "tz1MDU45gNc9Ko1Q9obcz6hQkKSMiQRib6GZ",
						Fee:          big.NewInt(2837),
						Counter:      big.NewInt(266515),
						GasLimit:     big.NewInt(11633),
						StorageLimit: big.NewInt(0),
					},
					Rollup: "txr1V16e1hXyVKndP4aE8cujRfryoHTiHK9fG",
				},
				Level:           11,
				Message:         RollupMessageBatch{0x1, 0xb2, 0x53, 0xb, 0xd9, 0xf4, 0xd5, 0x94, 0xee, 0x61, 0x16, 0x28, 0x6c, 0xbb, 0x4, 0x5a, 0x97, 0x23, 0x5, 0xe3, 0x8e, 0x63, 0x65, 0xb3, 0x96, 0xf4, 0x9d, 0x15, 0x38, 0x15, 0xfb, 0xdd, 0x15, 0xc8, 0x97, 0x4b, 0x7f, 0xdc, 0x50, 0xae, 0xe4, 0xbc, 0x3f, 0x81, 0x95, 0xe9, 0x50, 0x75, 0xab, 0xf, 0xca, 0x5d, 0x31, 0x92, 0x79, 0x17, 0xed, 0xe7, 0xa4, 0x8, 0xfe, 0x70, 0xc6, 0x1c, 0xd4, 0xa0, 0x52, 0x5b, 0x28, 0x36, 0xec, 0xa0, 0xe7, 0x97, 0xcd, 0xf9, 0xae, 0x9b, 0x3b, 0xf5, 0x87, 0x35, 0xfd, 0x62, 0xa7, 0xbf, 0x21, 0x77, 0x5d, 0x46, 0x94, 0xa, 0xe9, 0xbd, 0x83, 0xa8, 0xd5, 0x1, 0x13, 0x1, 0x87, 0xe8, 0xc6, 0x31, 0xab, 0xa4, 0x1d, 0x88, 0xa6, 0x7d, 0xa4, 0x9c, 0xf5, 0xf4, 0xdb, 0x94, 0x7f, 0xdf, 0x5a, 0x76, 0x8, 0x4f, 0x1d, 0x4b, 0x6c, 0x14, 0x53, 0x1f, 0x65, 0x82, 0xb2, 0x39, 0xdb, 0x26, 0xdd, 0x3, 0x75, 0xca, 0x71, 0x72, 0xcd, 0xbe, 0xcd, 0x8b, 0x6f, 0x8, 0xf, 0xfa, 0x58, 0xc7, 0x48, 0xf8, 0x3c, 0xc7, 0xa2, 0xaf, 0xce, 0x16, 0x4c, 0x1b, 0xcc, 0x53, 0x71, 0x2f, 0xf5, 0xa9, 0xe5, 0xc, 0x39, 0xfb, 0x1, 0x72, 0xac, 0xda, 0xa},
				MessagePosition: big.NewInt(0),
				MessagePath: []string{
					"txi1WZKF1fkUWfKbmaHbb5b8gn68rKSyUy4k7NnSVY4p79BKYz5RB",
				},
				MessageResultHash: "txmr344vtdPzvWsfnoSd3mJ3MCFA5ehKLQs1pK9WGcX4FEACg1rVgC",
				MessageResultPath: []string{
					"txM2eYt63gJ98tv3z4nj3aWPMzpjLnW9xpUdmz4ftMnbvNG34Y4wB",
				},
				PreviousMessageResult: MessageResult{
					ContextHash:      "CoVUv68XdJts8f6Ysaoxm4jnt4JKXfqx8WYVFnkj2UFfgKHJUrLs",
					WithdrawListHash: "txw1sFoLju3ySMAdY6v1dcHUMqJ4Zxc1kcynC8xkYgCmH6bpNSDhV",
				},
				PreviousMessageResultPath: []string{
					"txM2eYt63gJ98tv3z4nj3aWPMzpjLnW9xpUdmz4ftMnbvNG34Y4wB",
				},
			},
		},
		{
			Kind: "tx_rollup_dispatch_tickets",
			Data: "9d00fdf904a319c1fb0f073cd2ebc7c0ab71466a1781c306f5b30f822256767fb41cd9acc4982951d7576ecb709b849ba7a0000000043e3eddcb4f9ebfd4a7b0e7aca02570efaf50eb79114690c74d7f802bd1d553cd000000000000002000000000000000000000000000000000000000000000000000000000000000000000004900000012010000000d74686972642d6465706f736974000000020368013f4a259911e55e00ad15e1b23cacc020dd853bcc00000200fdf904a319c1fb0f073cd2ebc7c0ab71466a1781",
			Operation: &OpTxRollupDispatchTickets{
				Rollup: Rollup{
					Manager: Manager{
						Source:       "tz1inuxjXxKhd9e4b97N1Wgz7DwmZSxFcDpM",
						Fee:          big.NewInt(835),
						Counter:      big.NewInt(252405),
						GasLimit:     big.NewInt(4354),
						StorageLimit: big.NewInt(86),
					},
					Rollup: "txr1YMZxstAHqQ9V313sYjLBCHBXsvSmDZuTs",
				},
				Level:        4,
				ContextHash:  "CoV7iqRirVx7sZa5TAK9ymoEJBrW6z4hwwrzMhz6YLeHYXrQwRWG",
				MessageIndex: 0,
				MessageResultPath: []string{
					"txM2eYt63gJ98tv3z4nj3aWPMzpjLnW9xpUdmz4ftMnbvNG34Y4wB",
				},
				TicketsInfo: []TicketInfo{
					{
						Contents: []uint8{0x1, 0x0, 0x0, 0x0, 0xd, 0x74, 0x68, 0x69, 0x72, 0x64, 0x2d, 0x64, 0x65, 0x70, 0x6f, 0x73, 0x69, 0x74},
						Ty:       []uint8{0x3, 0x68},
						Ticketer: "KT1EMQxfYVvhTJTqMiVs2ho2dqjbYfYKk6BY",
						Amount:   int64(2),
						Claimer:  "tz1inuxjXxKhd9e4b97N1Wgz7DwmZSxFcDpM",
					},
				},
			},
		},
		{
			Kind: "transfer_ticket",
			Data: "9e00fdf904a319c1fb0f073cd2ebc7c0ab71466a1781c306f5b30f82225600000012010000000d74686972642d6465706f736974000000020368013f4a259911e55e00ad15e1b23cacc020dd853bcc0001013f4a259911e55e00ad15e1b23cacc020dd853bcc0000000003787878",
			Operation: &OpTransferTicket{
				Manager: Manager{
					Source:       "tz1inuxjXxKhd9e4b97N1Wgz7DwmZSxFcDpM",
					Fee:          big.NewInt(835),
					Counter:      big.NewInt(252405),
					GasLimit:     big.NewInt(4354),
					StorageLimit: big.NewInt(86),
				},
				TicketContents: []uint8{0x1, 0x0, 0x0, 0x0, 0xd, 0x74, 0x68, 0x69, 0x72, 0x64, 0x2d, 0x64, 0x65, 0x70, 0x6f, 0x73, 0x69, 0x74},
				TicketTy:       []uint8{0x3, 0x68},
				TicketTicketer: "KT1EMQxfYVvhTJTqMiVs2ho2dqjbYfYKk6BY",
				TicketAmount:   big.NewInt(1),
				Destination:    "KT1EMQxfYVvhTJTqMiVs2ho2dqjbYfYKk6BY",
				Entrypoint:     "xxx",
			},
		},
	},
}

func TestOperations(t *testing.T) {
	for proto, cases := range testData {
		t.Run(proto, func(t *testing.T) {
			for _, c := range cases {
				t.Run(c.Kind, func(t *testing.T) {
					data, err := hex.DecodeString(c.Data)
					require.NoError(t, err)
					opdata := data[32:] // skip branch
					op, err := parseOperation(&opdata)
					require.NoError(t, err)
					require.Equal(t, c.Operation, op)
				})
			}
		})
	}
}

func TestOperationsRaw(t *testing.T) {
	for proto, cases := range testDataRaw {
		t.Run(proto, func(t *testing.T) {
			for _, c := range cases {
				t.Run(c.Kind, func(t *testing.T) {
					data, err := hex.DecodeString(c.Data)
					require.NoError(t, err)
					op, err := parseOperation(&data)
					require.NoError(t, err)
					require.Equal(t, c.Operation, op)
				})
			}
		})
	}
}
