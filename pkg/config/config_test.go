package config

import (
	"testing"

	"github.com/ecadlabs/gotez/b58"
	"github.com/ecadlabs/signatory/pkg/crypt"
	"github.com/ecadlabs/signatory/pkg/hashmap"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

type testCase struct {
	title               string
	src                 string
	expect              *Config
	expectParseError    string
	expectValidateError string
}

func mustPKH(src string) crypt.PublicKeyHash {
	pkh, err := b58.ParsePublicKeyHash([]byte(src))
	if err != nil {
		panic(err)
	}
	return pkh
}

var testCases = []testCase{
	{
		title: "Valid",
		src: `---
base_dir: $HOME/.signatory
server:
  address: :6732
  utility_address: :9583

vaults:
  kms:
    driver: cloudkms
    config:
      project: signatory
      location: europe-north1
      key_ring: hsm-ring

tezos:
  tz1Wz4ZabKRsz842Xuzy4a7CcWADfPVsPKus:

  tz3MhmeqpudUqEX8PYTbNDF3CVcnnjNQoo8N:
    log_payloads: true
    allow:
      generic:
        - transaction
        - endorsement
      block:
      endorsement:
`,
		expect: &Config{
			BaseDir: "$HOME/.signatory",
			Server: ServerConfig{
				Address:        ":6732",
				UtilityAddress: ":9583",
			},
			Vaults: map[string]*VaultConfig{
				"kms": {
					Driver: "cloudkms",
					Config: yaml.Node{
						Kind: 4,
						Tag:  "!!map",
						Content: []*yaml.Node{
							{
								Kind:   8,
								Tag:    "!!str",
								Value:  "project",
								Line:   11,
								Column: 7,
							},
							{
								Kind:   8,
								Tag:    "!!str",
								Value:  "signatory",
								Line:   11,
								Column: 16,
							},
							{
								Kind:   8,
								Tag:    "!!str",
								Value:  "location",
								Line:   12,
								Column: 7,
							},
							{
								Kind:   8,
								Tag:    "!!str",
								Value:  "europe-north1",
								Line:   12,
								Column: 17,
							},
							{
								Kind:   8,
								Tag:    "!!str",
								Value:  "key_ring",
								Line:   13,
								Column: 7,
							},
							{
								Kind:   8,
								Tag:    "!!str",
								Value:  "hsm-ring",
								Line:   13,
								Column: 17,
							},
						},
						Line:   11,
						Column: 7,
					},
				},
			},
			Tezos: hashmap.NewPublicKeyHashMap([]hashmap.KV[crypt.PublicKeyHash, *TezosPolicy]{
				{
					Key: mustPKH("tz1Wz4ZabKRsz842Xuzy4a7CcWADfPVsPKus"),
					Val: nil,
				},
				{
					Key: mustPKH("tz3MhmeqpudUqEX8PYTbNDF3CVcnnjNQoo8N"),
					Val: &TezosPolicy{
						LogPayloads: true,
						Allow: map[string][]string{
							"generic":     {"transaction", "endorsement"},
							"block":       nil,
							"endorsement": nil,
						},
					},
				},
			}),
		},
	},
	{
		title: "InvalidBase58",
		src: `---
base_dir: $HOME/.signatory
server:
  address: :6732
  utility_address: :9583

vaults:
  kms:
    driver: cloudkms
    config:
      project: signatory
      location: europe-north1
      key_ring: hsm-ring

tezos:
  111111111111111111111111111111111111:
`,
		expectParseError: "gotez: base58Check decoding error: invalid checksum",
	},
	{
		title: "InvalidType",
		src: `---
base_dir: $HOME/.signatory
server:
  address: :6732
  utility_address: :9583

vaults:
  kms:
    driver: cloudkms
    config:
      project: signatory
      location: europe-north1
      key_ring: hsm-ring

tezos:
  edpkv45regue1bWtuHnCgLU8xWKLwa9qRqv4gimgJKro4LSc3C5VjV:
`,
		expectParseError: "gotez: unknown public key prefix",
	},
	{
		title: "NoBaseDir",
		src: `---
server:
  address: :6732
  utility_address: :9583

vaults:
  kms:
    driver: cloudkms
    config:
      project: signatory
      location: europe-north1
      key_ring: hsm-ring

tezos:
  tz1Wz4ZabKRsz842Xuzy4a7CcWADfPVsPKus:

  tz3MhmeqpudUqEX8PYTbNDF3CVcnnjNQoo8N:
    log_payloads: true
    allow:
      generic:
        - transaction
        - endorsement
      block:
      endorsement:
`,
		expect: &Config{
			Server: ServerConfig{
				Address:        ":6732",
				UtilityAddress: ":9583",
			},
			Vaults: map[string]*VaultConfig{
				"kms": {
					Driver: "cloudkms",
					Config: yaml.Node{
						Kind: 4,
						Tag:  "!!map",
						Content: []*yaml.Node{
							{
								Kind:   8,
								Tag:    "!!str",
								Value:  "project",
								Line:   10,
								Column: 7,
							},
							{
								Kind:   8,
								Tag:    "!!str",
								Value:  "signatory",
								Line:   10,
								Column: 16,
							},
							{
								Kind:   8,
								Tag:    "!!str",
								Value:  "location",
								Line:   11,
								Column: 7,
							},
							{
								Kind:   8,
								Tag:    "!!str",
								Value:  "europe-north1",
								Line:   11,
								Column: 17,
							},
							{
								Kind:   8,
								Tag:    "!!str",
								Value:  "key_ring",
								Line:   12,
								Column: 7,
							},
							{
								Kind:   8,
								Tag:    "!!str",
								Value:  "hsm-ring",
								Line:   12,
								Column: 17,
							},
						},
						Line:   10,
						Column: 7,
					},
				},
			},
			Tezos: hashmap.NewPublicKeyHashMap([]hashmap.KV[crypt.PublicKeyHash, *TezosPolicy]{
				{
					Key: mustPKH("tz1Wz4ZabKRsz842Xuzy4a7CcWADfPVsPKus"),
					Val: nil,
				},
				{
					Key: mustPKH("tz3MhmeqpudUqEX8PYTbNDF3CVcnnjNQoo8N"),
					Val: &TezosPolicy{
						LogPayloads: true,
						Allow: map[string][]string{
							"generic":     {"transaction", "endorsement"},
							"block":       nil,
							"endorsement": nil,
						},
					},
				},
			}),
		},
		expectValidateError: "Key: 'Config.BaseDir' Error:Field validation for 'BaseDir' failed on the 'required' tag",
	},
	{
		title: "InvalidAddress",
		src: `---
base_dir: $HOME/.signatory
server:
  address: xxxx
  utility_address: :9583

vaults:
  kms:
    driver: cloudkms
    config:
      project: signatory
      location: europe-north1
      key_ring: hsm-ring

tezos:
  tz1Wz4ZabKRsz842Xuzy4a7CcWADfPVsPKus:

  tz3MhmeqpudUqEX8PYTbNDF3CVcnnjNQoo8N:
    log_payloads: true
    allow:
      generic:
        - transaction
        - endorsement
      block:
      endorsement:
`,
		expect: &Config{
			BaseDir: "$HOME/.signatory",
			Server: ServerConfig{
				Address:        "xxxx",
				UtilityAddress: ":9583",
			},
			Vaults: map[string]*VaultConfig{
				"kms": {
					Driver: "cloudkms",
					Config: yaml.Node{
						Kind: 4,
						Tag:  "!!map",
						Content: []*yaml.Node{
							{
								Kind:   8,
								Tag:    "!!str",
								Value:  "project",
								Line:   11,
								Column: 7,
							},
							{
								Kind:   8,
								Tag:    "!!str",
								Value:  "signatory",
								Line:   11,
								Column: 16,
							},
							{
								Kind:   8,
								Tag:    "!!str",
								Value:  "location",
								Line:   12,
								Column: 7,
							},
							{
								Kind:   8,
								Tag:    "!!str",
								Value:  "europe-north1",
								Line:   12,
								Column: 17,
							},
							{
								Kind:   8,
								Tag:    "!!str",
								Value:  "key_ring",
								Line:   13,
								Column: 7,
							},
							{
								Kind:   8,
								Tag:    "!!str",
								Value:  "hsm-ring",
								Line:   13,
								Column: 17,
							},
						},
						Line:   11,
						Column: 7,
					},
				},
			},
			Tezos: hashmap.NewPublicKeyHashMap([]hashmap.KV[crypt.PublicKeyHash, *TezosPolicy]{
				{
					Key: mustPKH("tz1Wz4ZabKRsz842Xuzy4a7CcWADfPVsPKus"),
					Val: nil,
				},
				{
					Key: mustPKH("tz3MhmeqpudUqEX8PYTbNDF3CVcnnjNQoo8N"),
					Val: &TezosPolicy{
						LogPayloads: true,
						Allow: map[string][]string{
							"generic":     {"transaction", "endorsement"},
							"block":       nil,
							"endorsement": nil,
						},
					},
				},
			}),
		},
		expectValidateError: "Key: 'Config.Server.Address' Error:Field validation for 'Address' failed on the 'hostname_port' tag",
	},
	{
		title: "EmptyVaultData",
		src: `---
base_dir: $HOME/.signatory
server:
  address: :6732
  utility_address: :9583

vaults:
  kms:

tezos:
  tz1Wz4ZabKRsz842Xuzy4a7CcWADfPVsPKus:

  tz3MhmeqpudUqEX8PYTbNDF3CVcnnjNQoo8N:
    log_payloads: true
    allow:
      generic:
        - transaction
        - endorsement
      block:
      endorsement:
`,
		expect: &Config{
			BaseDir: "$HOME/.signatory",
			Server: ServerConfig{
				Address:        ":6732",
				UtilityAddress: ":9583",
			},
			Vaults: map[string]*VaultConfig{
				"kms": nil,
			},
			Tezos: hashmap.NewPublicKeyHashMap([]hashmap.KV[crypt.PublicKeyHash, *TezosPolicy]{
				{
					Key: mustPKH("tz1Wz4ZabKRsz842Xuzy4a7CcWADfPVsPKus"),
					Val: nil,
				},
				{
					Key: mustPKH("tz3MhmeqpudUqEX8PYTbNDF3CVcnnjNQoo8N"),
					Val: &TezosPolicy{
						LogPayloads: true,
						Allow: map[string][]string{
							"generic":     {"transaction", "endorsement"},
							"block":       nil,
							"endorsement": nil,
						},
					},
				},
			}),
		},
		expectValidateError: "Key: 'Config.Vaults[kms]' Error:Field validation for 'Vaults[kms]' failed on the 'required' tag",
	},
}

func TestConfig(t *testing.T) {
	for _, test := range testCases {
		t.Run(test.title, func(t *testing.T) {
			var result Config
			err := yaml.Unmarshal([]byte(test.src), &result)
			if test.expectParseError != "" {
				require.EqualError(t, err, test.expectParseError)
			} else {
				require.NoError(t, err)
				require.Equal(t, test.expect, &result)
				err := Validator().Struct(&result)
				if test.expectValidateError != "" {
					require.EqualError(t, err, test.expectValidateError)
				} else {
					require.NoError(t, err)
				}
			}
		})
	}
}
