package tezos

import (
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBlock(t *testing.T) {
	// tezt/_regressions/encoding/ithaca.block_header.out
	data := "00000533010e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8000000005e9dcbb00242e9bc4583d4f9fa6ba422733f45d3a44397141a953d2237bf8df62e5046eef700000011000000010100000008000000000000000a4c7319284b55068bb7c4e0b9f8585729db7fb27ab4ca9cff2038a1fc324f650c000000000000000000000000000000000000000000000000000000000000000000000000101895ca00000000ff043691f53c02ca1ac6f1a0c1586bf77973e04c2d9b618a8309e79651daf0d5580066804fe735e06e97e26da8236b6341b91c625d5e82b3524ec0a88cc982365e70f8a5b9bc65df2ea6d21ee244cc3a96fb33031c394c78b1179ff1b8a44237740c"
	expect := BlockHeader{
		ShellBlockHeader: ShellBlockHeader{
			Level:          1331,
			Proto:          1,
			Predecessor:    "BKpbfCvh777DQHnXjU2sqHvVUNZ7dBAdqEfKkdw8EGSkD9LSYXb",
			Timestamp:      strTime("2020-04-20 16:20:00 +0000 UTC"),
			ValidationPass: 2,
			OperationsHash: "LLoZqBDX1E2ADRXbmwYo8VtMNeHG6Ygzmm4Zqv97i91UPBQHy9Vq3",
			Fitness: [][]uint8{
				{0x01},
				{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a},
			},
			Context: "CoVDyf9y9gHfAkPWofBJffo4X4bWjmehH2LeVonDcCKKzyQYwqdk",
		},
		PayloadHash:               "vh1g87ZG6scSYxKhspAUzprQVuLAyoa5qMBKcUfjgnQGnFb3dJcG",
		PayloadRound:              0,
		ProofOfWorkNonce:          []uint8{0x10, 0x18, 0x95, 0xca, 0x00, 0x00, 0x00, 0x00},
		SeedNonceHash:             "nceUFoeQDgkJCmzdMWh19ZjBYqQD3N9fe6bXQ1ZsUKKvMn7iun5Z3",
		LiquidityBakingToggleVote: "on",
	}
	d, err := hex.DecodeString(data)
	require.NoError(t, err)
	bh, err := parseUnsignedBlockHeader(&d)
	require.NoError(t, err)
	require.Equal(t, &expect, bh)
}

func TestRequest(t *testing.T) {
	type testCase struct {
		data string
		msg  UnsignedMessage
	}

	var cases = []testCase{
		{
			data: "12ed9d217c2f50673bab6b20dfb0a88ca93b4a0c72a34c807af5dffbece2cba3d2b509835f14006000000002000000041f1ebb39759cc957216f88fb4d005abc206fb00a53f8d57ac01be00c084cba97",
			msg: &PreendorsementRequest{
				ChainID: "NetXxkAx4woPLyu",
				Branch:  "BL57uk2FrPckCtzBQwaQV1bYtPPShcDCqMShArucaBSpqtmDdRn",
				OpPreendorsement: &OpPreendorsement{
					Slot:             96,
					Level:            2,
					Round:            4,
					BlockPayloadHash: "vh1uq2uMDFaJAZZcydX5QeW2dG3Mpc2y31tT621LuEppkxfy11SK",
				},
			},
		},
		{
			data: "12ed9d217c2f50673bab6b20dfb0a88ca93b4a0c72a34c807af5dffbece2cba3d2b509835f1400600000000200000005554ff14bf2d6f40d0176221a6eaa385e7fcefe272063bf9d156baf5da3a0a012",
			msg: &PreendorsementRequest{
				ChainID: "NetXxkAx4woPLyu",
				Branch:  "BL57uk2FrPckCtzBQwaQV1bYtPPShcDCqMShArucaBSpqtmDdRn",
				OpPreendorsement: &OpPreendorsement{
					Slot:             96,
					Level:            2,
					Round:            5,
					BlockPayloadHash: "vh2KhJSHF6yD2zYxJXXGf2QYgqs5X3bstEGpwECVVHtDdoSnaVsM",
				},
			},
		},
		{
			data: "12ed9d217cfc81eee810737b04018acef4db74d056b79edc43e6be46cae7e4c217c22a82f01400120000518d0000000003e7ea1f67dbb0bb6cfa372cb092cd9cf786b4f1b5e5139da95b915fb95e698d",
			msg: &PreendorsementRequest{
				ChainID: "NetXxkAx4woPLyu",
				Branch:  "BMdVJUZrmcLJBnXsxdJLJaTDFJYyqarwmst7hpPu53Z3xLPtnMF",
				OpPreendorsement: &OpPreendorsement{
					Slot:             18,
					Level:            20877,
					Round:            0,
					BlockPayloadHash: "vh1hqtJCryS2Uzb8KDU2PAp33U1nDCeUB4g9yWKTjgVhiy4x9pQA",
				},
			},
		},
		{
			data: "13ed9d217cfc81eee810737b04018acef4db74d056b79edc43e6be46cae7e4c217c22a82f01500120000518d0000000003e7ea1f67dbb0bb6cfa372cb092cd9cf786b4f1b5e5139da95b915fb95e698d",
			msg: &TenderbakeEndorsementRequest{
				ChainID: "NetXxkAx4woPLyu",
				Branch:  "BMdVJUZrmcLJBnXsxdJLJaTDFJYyqarwmst7hpPu53Z3xLPtnMF",
				OpTenderbakeEndorsement: &OpTenderbakeEndorsement{
					Slot:             18,
					Level:            20877,
					Round:            0,
					BlockPayloadHash: "vh1hqtJCryS2Uzb8KDU2PAp33U1nDCeUB4g9yWKTjgVhiy4x9pQA",
				},
			},
		},
		{
			data: "11ed9d217c0000518e0118425847ac255b6d7c30ce8fec23b8eaf13b741de7d18509ac2ef83c741209630000000061947af504805682ea5d089837764b3efcc90b91db24294ff9ddb66019f332ccba17cc4741000000210000000102000000040000518e0000000000000004ffffffff0000000400000000eb1320a71e8bf8b0162a3ec315461e9153a38b70d00d5dde2df85eb92748f8d068d776e356683a9e23c186ccfb72ddc6c9857bb1704487972922e7c89a7121f800000000a8e1dd3c000000000000",
			msg: &TenderbakeBlockRequest{
				ChainID: "NetXxkAx4woPLyu",
				BlockHeader: &BlockHeader{
					ShellBlockHeader: ShellBlockHeader{
						Level:          20878,
						Proto:          1,
						Predecessor:    "BKty19HXfE15jjeLFCTxpEZRXRVkQKGBcArzn4eAgMYTrdaf6xc",
						Timestamp:      strTime("2021-11-17 03:45:57 +0000 UTC"),
						ValidationPass: 4,
						OperationsHash: "LLoaJEEVU5t92V3PEFG9SZ6JrgG3AAwLhKXkXxHjfiZFxLZeqaRcg",
						Fitness: [][]uint8{
							{0x02},
							{0x00, 0x00, 0x51, 0x8e},
							{},
							{0xff, 0xff, 0xff, 0xff},
							{0x00, 0x00, 0x00, 0x00},
						},
						Context: "CoWRqXN1hCqPoLNF5K53DkcqHSHA9638oXnyhg5nBBsK1gNVAQdZ",
					},
					PayloadHash:               "vh2UJ9qvkLHcFbiotR462Ni84QU7xJ83fNwspoo9kq7spoNeSMkH",
					PayloadRound:              0,
					ProofOfWorkNonce:          []uint8{0xa8, 0xe1, 0xdd, 0x3c, 0x00, 0x00, 0x00, 0x00},
					LiquidityBakingToggleVote: "on",
				},
			},
		},
		{
			data: "12ed9d217c18425847ac255b6d7c30ce8fec23b8eaf13b741de7d18509ac2ef83c741209631400000000518e00000001521eef1af112fc98def0da6588945c7c483b532334afacd247c6e959467d1946",
			msg: &PreendorsementRequest{
				ChainID: "NetXxkAx4woPLyu",
				Branch:  "BKty19HXfE15jjeLFCTxpEZRXRVkQKGBcArzn4eAgMYTrdaf6xc",
				OpPreendorsement: &OpPreendorsement{
					Slot:             0,
					Level:            20878,
					Round:            1,
					BlockPayloadHash: "vh2JHnDVQe3AjR4G2GioKa2B7toaM1zYHNN9Er5u8ZexMVnt9owF",
				},
			},
		},
		{
			data: "13ed9d217c18425847ac255b6d7c30ce8fec23b8eaf13b741de7d18509ac2ef83c741209631500000000518e00000001521eef1af112fc98def0da6588945c7c483b532334afacd247c6e959467d1946",
			msg: &TenderbakeEndorsementRequest{
				ChainID: "NetXxkAx4woPLyu",
				Branch:  "BKty19HXfE15jjeLFCTxpEZRXRVkQKGBcArzn4eAgMYTrdaf6xc",
				OpTenderbakeEndorsement: &OpTenderbakeEndorsement{
					Slot:             0,
					Level:            20878,
					Round:            1,
					BlockPayloadHash: "vh2JHnDVQe3AjR4G2GioKa2B7toaM1zYHNN9Er5u8ZexMVnt9owF",
				},
			},
		},
		{
			data: "11ed9d217c0000518e0118425847ac255b6d7c30ce8fec23b8eaf13b741de7d18509ac2ef83c741209630000000061947b4004002f50a59970f77d844808d67cf0c39bc0680900a608720051ecb334d47cf1fc000000250000000102000000040000518e000000040000000100000004ffffffff00000004000000022d4fd437220316d3da0604b9d4c6b631931b3e5ca6373e1dcb9217ed163a5eb6521eef1af112fc98def0da6588945c7c483b532334afacd247c6e959467d194600000001a8e1dd3c000000000000",
			msg: &TenderbakeBlockRequest{
				ChainID: "NetXxkAx4woPLyu",
				BlockHeader: &BlockHeader{
					ShellBlockHeader: ShellBlockHeader{
						Level:          20878,
						Proto:          1,
						Predecessor:    "BKty19HXfE15jjeLFCTxpEZRXRVkQKGBcArzn4eAgMYTrdaf6xc",
						Timestamp:      strTime("2021-11-17 03:47:12 +0000 UTC"),
						ValidationPass: 4,
						OperationsHash: "LLoZKnjY7Ad48r91VJfy8AbCr8Cksa5qYHNWV5HMfDS97rc9nrJwp",
						Fitness: [][]uint8{
							{0x02},
							{0x00, 0x00, 0x51, 0x8e},
							{0x00, 0x00, 0x00, 0x01},
							{0xff, 0xff, 0xff, 0xff},
							{0x00, 0x00, 0x00, 0x02},
						},
						Context: "CoUzGHYfsjAYzGRXrdRGsHPBegYPyGZhERubtd4g4C4Q1UxG3pcF",
					},
					PayloadHash:               "vh2JHnDVQe3AjR4G2GioKa2B7toaM1zYHNN9Er5u8ZexMVnt9owF",
					PayloadRound:              1,
					ProofOfWorkNonce:          []uint8{0xa8, 0xe1, 0xdd, 0x3c, 0x00, 0x00, 0x00, 0x00},
					LiquidityBakingToggleVote: "on",
				},
			},
		},
		{
			data: "11af1864d9000bb28703a4852fc6cc0ecde11c599941651e4a532197a48c084e2f5b75a9a8b643534e910000000062bb3552042c39b4d080c1575898d04ce9494a92f01dc383741a5386892d73fbf1c3b07bcc00000021000000010200000004000bb2870000000000000004ffffffff00000004000000014d33938f492722277f1d2f9a63e797c5c5b207dec6120859fe4384107fe6352daafc5d3c600812134143c1be015d89a906264547aff9f2ea3026908f82d5139e00000001cb9f439e19d500000002",
			msg: &TenderbakeBlockRequest{
				ChainID: "NetXnHfVqm9iesp",
				BlockHeader: &BlockHeader{
					ShellBlockHeader: ShellBlockHeader{
						Level:          766599,
						Proto:          3,
						Predecessor:    "BLxjnUUjCqzB3MxfQpPB3ebLDr84vzPZ8hiREB7QEFbMECeaKcw",
						Timestamp:      strTime("2022-06-28 17:07:30 +0000 UTC"),
						ValidationPass: 4,
						OperationsHash: "LLoZfBh66rRrSZhwNArQJgL3xyUPgdEyqWUnsx6Avr3fpA8WLNiot",
						Fitness: [][]uint8{
							{0x02},
							{0x00, 0x0b, 0xb2, 0x87},
							{},
							{0xff, 0xff, 0xff, 0xff},
							{0x00, 0x00, 0x00, 0x01},
						},
						Context: "CoVEJs57DVdG1roZD5YPjZ3jEHGvoiBrYEiXS2B37Vvj4xg8KRmy",
					},
					PayloadHash:               "vh2yRiWnsKxkSP8AweaWr5nXBhYutgSvcCtNEpTJBTKN1aoXjzyw",
					PayloadRound:              1,
					ProofOfWorkNonce:          []uint8{0xcb, 0x9f, 0x43, 0x9e, 0x19, 0xd5, 0x00, 0x00},
					LiquidityBakingToggleVote: "pass",
				},
			},
		},
	}

	for _, c := range cases {
		t.Run(fmt.Sprintf("%T", c.msg), func(t *testing.T) {
			d, err := hex.DecodeString(c.data)
			require.NoError(t, err)
			msg, err := parseRequest(&d)
			require.NoError(t, err)
			switch msg.(type) {
			case *EmmyBlockRequest, *TenderbakeBlockRequest:
			default:
				assert.Empty(t, d)
			}
			// spew.Dump(msg)
			assert.Equal(t, c.msg, msg)
		})
	}
}
