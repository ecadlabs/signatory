package rpc

import (
	"testing"

	"github.com/ecadlabs/signatory/pkg/vault/nitro/rpc/testdata"
	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"
)

func newVal[T any](v T) *T { return &v }

func TestUnmarshal(t *testing.T) {
	type testData struct {
		name   string
		src    []byte
		val    any
		expect any
	}

	tests := []testData{
		{
			name: "Initialize",
			src:  testdata.RequestInitialize,
			val:  new(Request[AWSCredentials]),
			expect: &Request[AWSCredentials]{
				Initialize: &AWSCredentials{
					AccessKeyID:     "access_key",
					SecretAccessKey: "secret_key",
					SessionToken:    newVal("token"),
				},
			},
		},
		{
			name:   "Import",
			src:    testdata.RequestImport,
			val:    new(Request[AWSCredentials]),
			expect: &Request[AWSCredentials]{Import: []byte{0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8}},
		},
		{
			name:   "Generate",
			src:    testdata.RequestGenerate,
			val:    new(Request[AWSCredentials]),
			expect: &Request[AWSCredentials]{Generate: newVal(KeySecp256k1)},
		},
		{
			name:   "Sign",
			src:    testdata.RequestSign,
			val:    new(Request[AWSCredentials]),
			expect: &Request[AWSCredentials]{Sign: &signRequest{Handle: 0, Msg: []byte{0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8}}},
		},
		{
			name: "SignWith",
			src:  testdata.RequestSignWith,
			val:  new(Request[AWSCredentials]),
			expect: &Request[AWSCredentials]{SignWith: &signWithRequest{
				KeyData: []byte{0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8},
				Msg:     []byte{9, 10, 11, 12, 13, 14, 15, 16, 17},
			}},
		},
		{
			name:   "PublicKey",
			src:    testdata.RequestPublicKey,
			val:    new(Request[AWSCredentials]),
			expect: &Request[AWSCredentials]{PublicKey: newVal(uint64(0))},
		},
		{
			name: "Ok",
			src:  testdata.ReplyOk,
			val:  new(Result[*struct{}]),
			expect: &Result[*struct{}]{
				Ok: nil,
			},
		},
		{
			name: "EdOk",
			src:  testdata.ReplyImportEdOk,
			val:  new(Result[*importResult]),
			expect: &Result[*importResult]{Ok: &importResult{
				PublicKey: PublicKey{
					Ed25519: []byte{0x31, 0x08, 0x8b, 0x5a, 0xdd, 0x36, 0xfd, 0x58, 0x99, 0x15, 0xed, 0xf6, 0xd7, 0x18, 0x25, 0xf4, 0xee, 0xdb, 0xaf, 0x89, 0x01, 0xcf, 0xef, 0x93, 0xec, 0xe0, 0x5d, 0xef, 0xe5, 0x85, 0x2f, 0xaa},
				},
				Handle: 0,
			}},
		},
		{
			name: "ImportErr",
			src:  testdata.ReplyImportErr,
			val:  new(Result[*importResult]),
			expect: &Result[*importResult]{Err: &RPCError{
				Message: "message0",
				Source: &RPCError{
					Message: "message1",
				},
			}},
		},
		{
			name: "GenerateSecp",
			src:  testdata.ReplyGenerateSecp,
			val:  new(Result[*generateResult]),
			expect: &Result[*generateResult]{Ok: &generateResult{
				PrivateKey: []byte{0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8},
				PublicKey: PublicKey{
					Secp256k1: []byte{
						0x30, 0x56, 0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x05, 0x2b,
						0x81, 0x04, 0x00, 0x0a, 0x03, 0x42, 0x00, 0x04, 0x4b, 0x9a, 0x55, 0x95, 0x4c, 0x3e, 0x66, 0x3f,
						0xac, 0xa1, 0x7f, 0x50, 0x29, 0x66, 0x23, 0xdc, 0xd6, 0x18, 0xd5, 0xaa, 0xe5, 0xb9, 0xeb, 0x09,
						0x07, 0x86, 0xb9, 0xd5, 0x44, 0xd1, 0x89, 0x11, 0x8c, 0x31, 0xc4, 0xe9, 0xab, 0x40, 0x40, 0x52,
						0x97, 0x5e, 0x6a, 0x73, 0x60, 0xc9, 0x7e, 0xd0, 0x82, 0x7a, 0x2b, 0x4e, 0xc7, 0xcb, 0x22, 0x6b,
						0xb0, 0xa7, 0x7c, 0x78, 0x90, 0x9b, 0xf6, 0x1e,
					},
				},
			}},
		},
		{
			name: "GenerateNist",
			src:  testdata.ReplyGenerateNist,
			val:  new(Result[*generateResult]),
			expect: &Result[*generateResult]{Ok: &generateResult{
				PrivateKey: []byte{0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8},
				PublicKey: PublicKey{
					P256: []byte{
						0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
						0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0x19, 0x19, 0x5a, 0x5d, 0x1c,
						0x58, 0x9b, 0x8d, 0x1c, 0x96, 0xf8, 0x30, 0x2a, 0x8b, 0x0f, 0xad, 0x7a, 0x24, 0xc2, 0x7b, 0xb7,
						0x6d, 0x94, 0x36, 0x23, 0x76, 0x83, 0x47, 0xc7, 0x86, 0x53, 0xc8, 0x59, 0x9c, 0x89, 0x51, 0xa4,
						0x3d, 0x14, 0x55, 0xb3, 0xad, 0x15, 0x3c, 0xbe, 0x13, 0x02, 0x4c, 0xe3, 0x1e, 0x8d, 0x51, 0x07,
						0x72, 0x5b, 0x88, 0x09, 0x43, 0x51, 0x06, 0x1d, 0x5d, 0x8a, 0xd2,
					},
				},
			}},
		},
		{
			name: "GenerateEd",
			src:  testdata.ReplyGenerateEd,
			val:  new(Result[*generateResult]),
			expect: &Result[*generateResult]{Ok: &generateResult{
				PrivateKey: []byte{0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8},
				PublicKey: PublicKey{
					Ed25519: []byte{
						0x68, 0x13, 0x51, 0xd5, 0x15, 0x8f, 0x32, 0x69, 0x80, 0x41, 0x58, 0x8f, 0x01, 0x0a, 0xc8, 0xaa,
						0xef, 0xa6, 0x20, 0x10, 0x38, 0x2f, 0x7e, 0x9b, 0xa4, 0xea, 0x31, 0x34, 0xaa, 0xc7, 0x88, 0x88,
					},
				},
			}},
		},
		{
			name: "GenerateBls",
			src:  testdata.ReplyGenerateBls,
			val:  new(Result[*generateResult]),
			expect: &Result[*generateResult]{Ok: &generateResult{
				PrivateKey: []byte{0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8},
				PublicKey: PublicKey{
					BLS: []byte{
						0xa9, 0x18, 0xc5, 0xf6, 0xf6, 0xbd, 0xff, 0x96, 0x15, 0xbb, 0x68, 0x55, 0xfb, 0x77, 0xbf, 0xa1,
						0x9f, 0x23, 0x21, 0xec, 0x1a, 0x0e, 0xc9, 0x1b, 0xac, 0x8f, 0xbc, 0x42, 0x2d, 0xc5, 0x6d, 0x05,
						0x19, 0x8b, 0x16, 0x35, 0xee, 0x64, 0x2f, 0xd5, 0x06, 0x52, 0xfc, 0x9d, 0x57, 0x50, 0x0c, 0xf2,
					},
				},
			}},
		},
		{
			name: "GenerateAndImport",
			src:  testdata.ReplyGenerateAndImport,
			val:  new(Result[*generateAndImportResult]),
			expect: &Result[*generateAndImportResult]{Ok: &generateAndImportResult{
				PrivateKey: []byte{0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8},
				PublicKey: PublicKey{
					Secp256k1: []byte{
						0x30, 0x56, 0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x05, 0x2b,
						0x81, 0x04, 0x00, 0x0a, 0x03, 0x42, 0x00, 0x04, 0x08, 0xfe, 0x97, 0x67, 0xfb, 0x93, 0x01, 0x43,
						0xeb, 0xc4, 0x9a, 0x95, 0xa7, 0x96, 0x9b, 0xb5, 0xb5, 0xb5, 0x90, 0x83, 0x0c, 0x92, 0xb1, 0x79,
						0x79, 0xf3, 0xd9, 0x3f, 0x67, 0x22, 0xb3, 0x73, 0xae, 0x37, 0xf1, 0x02, 0xc4, 0xcb, 0x8f, 0xb5,
						0x6d, 0xdd, 0x98, 0xfc, 0x43, 0xdc, 0x66, 0xae, 0x1b, 0xec, 0x46, 0x6c, 0xb9, 0x9e, 0x14, 0xfa,
						0x65, 0xf2, 0x86, 0x5f, 0x96, 0x69, 0x08, 0xf3,
					},
				},
				Handle: 0,
			}},
		},
		{
			name: "TrySignNist",
			src:  testdata.ReplyTrySignNist,
			val:  new(Result[*Signature]),
			expect: &Result[*Signature]{Ok: &Signature{
				P256: []byte{
					0x69, 0xe5, 0xc7, 0xed, 0x5e, 0x66, 0x8f, 0xb6, 0x35, 0x22, 0x2c, 0x6f, 0x07, 0x98, 0xde, 0x62,
					0x45, 0x76, 0x35, 0xd4, 0x20, 0x96, 0xca, 0xa3, 0xdc, 0xd2, 0x0e, 0x2b, 0x47, 0x8e, 0x90, 0x73,
					0xb2, 0x01, 0xe2, 0x90, 0x0a, 0x26, 0xe6, 0x49, 0x2c, 0x86, 0x2b, 0xc8, 0x2a, 0x2c, 0x24, 0x34,
					0x38, 0x6f, 0x7f, 0x72, 0x0c, 0xc1, 0xe0, 0xa9, 0xee, 0x49, 0x82, 0xa1, 0x8d, 0xf2, 0x71, 0x88,
				},
			}},
		},
		{
			name: "TrySignBls",
			src:  testdata.ReplyTrySignBls,
			val:  new(Result[*Signature]),
			expect: &Result[*Signature]{Ok: &Signature{
				BLS: []byte{
					0xa6, 0x93, 0x18, 0xe7, 0xed, 0x36, 0x5c, 0x0d, 0x14, 0x3c, 0x96, 0xf3, 0x99, 0x06, 0xfa, 0xec,
					0x64, 0x22, 0x2b, 0xc1, 0x53, 0x56, 0x01, 0x57, 0x3e, 0xc3, 0x99, 0x7a, 0x71, 0xf3, 0x38, 0xda,
					0xab, 0x36, 0x67, 0x88, 0xe7, 0x39, 0x8d, 0xaa, 0x00, 0x01, 0x61, 0x15, 0x59, 0xca, 0x39, 0x2f,
					0x01, 0x9a, 0x19, 0xbb, 0xe2, 0x08, 0x84, 0x37, 0xa5, 0xa5, 0x09, 0x38, 0xd1, 0x63, 0x81, 0x3d,
					0x50, 0x43, 0xa3, 0x59, 0xc9, 0x05, 0x9d, 0xf6, 0xd8, 0xf6, 0x16, 0xfa, 0x5e, 0x87, 0x26, 0x0a,
					0x3d, 0xf8, 0x10, 0xcf, 0xf1, 0x0f, 0x4d, 0xc5, 0xbf, 0x6c, 0x9b, 0x77, 0x2c, 0x6e, 0x6a, 0x55,
				},
			}},
		},
		{
			name: "TrySignEd",
			src:  testdata.ReplyTrySignEd,
			val:  new(Result[*Signature]),
			expect: &Result[*Signature]{Ok: &Signature{
				Ed25519: []byte{
					0x47, 0x87, 0x9c, 0x65, 0xbf, 0x31, 0x2c, 0xd7, 0xe1, 0x9b, 0x52, 0x09, 0xbe, 0xfc, 0x0d, 0x1f,
					0xf6, 0xca, 0x13, 0xe6, 0xc7, 0xfe, 0x9e, 0xec, 0x55, 0x5e, 0x35, 0x4f, 0xb2, 0xf1, 0xd5, 0x04,
					0x9a, 0x88, 0x61, 0x7e, 0xff, 0x46, 0xec, 0x44, 0x9b, 0xb7, 0x60, 0x83, 0xe2, 0xbd, 0x30, 0x80,
					0x49, 0xf7, 0x7c, 0x1f, 0x02, 0x3f, 0xbd, 0xfb, 0x98, 0x3b, 0x3f, 0xac, 0xae, 0xae, 0x70, 0x0e,
				},
			}},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			require.NoError(t, cbor.Unmarshal(test.src, test.val))
			require.Equal(t, test.expect, test.val)
		})
	}
}

func TestParsePublicKey(t *testing.T) {
	type testData struct {
		name string
		src  []byte
	}

	tests := []testData{
		{
			name: "GenerateSecp",
			src:  testdata.ReplyGenerateSecp,
		},
		{
			name: "GenerateNist",
			src:  testdata.ReplyGenerateNist,
		},
		{
			name: "GenerateEd",
			src:  testdata.ReplyGenerateEd,
		},
		{
			name: "GenerateBls",
			src:  testdata.ReplyGenerateBls,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var val Result[*generateResult]
			require.NoError(t, cbor.Unmarshal(test.src, &val))
			_, err := val.Ok.PublicKey.PublicKey()
			require.NoError(t, err)
		})
	}
}
