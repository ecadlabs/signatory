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
