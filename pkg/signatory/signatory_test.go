//go:build !integration

package signatory_test

import (
	"context"
	"encoding/hex"
	"testing"

	"github.com/ecadlabs/signatory/pkg/config"
	"github.com/ecadlabs/signatory/pkg/signatory"
	"github.com/ecadlabs/signatory/pkg/tezos"
	"github.com/ecadlabs/signatory/pkg/vault"
	"github.com/ecadlabs/signatory/pkg/vault/memory"
	"github.com/stretchr/testify/require"
	yaml "gopkg.in/yaml.v3"
)

const pk = "edsk4FTF78Qf1m2rykGpHqostAiq5gYW4YZEoGUSWBTJr2njsDHSnd"

func TestImport(t *testing.T) {
	conf := signatory.Config{
		Vaults:    map[string]*config.VaultConfig{"mock": {Driver: "mock"}},
		Watermark: signatory.IgnoreWatermark{},
		VaultFactory: vault.FactoryFunc(func(ctx context.Context, name string, conf *yaml.Node) (vault.Vault, error) {
			v, err := memory.New(nil, "Mock")
			if err != nil {
				return nil, err
			}
			return &memory.Importer{Vault: v}, nil
		}),
	}

	s, err := signatory.New(context.Background(), &conf)
	require.NoError(t, err)

	imported, err := s.Import(context.Background(), "mock", pk, nil, nil)
	require.NoError(t, err)
	require.Equal(t, "edpkv45regue1bWtuHnCgLU8xWKLwa9qRqv4gimgJKro4LSc3C5VjV", imported.PublicKey)
	require.Equal(t, "tz1LggX2HUdvJ1tF4Fvv8fjsrzLeW4Jr9t2Q", imported.PublicKeyHash)

	list, err := s.ListPublicKeys(context.Background())
	require.NoError(t, err)
	require.Equal(t, []*signatory.PublicKey{imported}, list)
}

func mustHex(s string) []byte {
	buf, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return buf
}

func TestPolicy(t *testing.T) {
	type testCase struct {
		title    string
		msg      []byte
		policy   signatory.Policy
		expected string
	}

	var cases = []testCase{
		{
			title: "block ok",
			msg:   mustHex("11ed9d217c0000518e0118425847ac255b6d7c30ce8fec23b8eaf13b741de7d18509ac2ef83c741209630000000061947af504805682ea5d089837764b3efcc90b91db24294ff9ddb66019f332ccba17cc4741000000210000000102000000040000518e0000000000000004ffffffff0000000400000000eb1320a71e8bf8b0162a3ec315461e9153a38b70d00d5dde2df85eb92748f8d068d776e356683a9e23c186ccfb72ddc6c9857bb1704487972922e7c89a7121f800000000a8e1dd3c000000000000"),
			policy: signatory.Policy{
				AllowedOperations: []string{"generic", "block", "endorsement"},
				AllowedKinds:      []string{"endorsement", "seed_nonce_revelation", "activate_account", "ballot", "reveal", "transaction", "origination", "delegation"},
				LogPayloads:       true,
			},
		},
		{
			title: "failing noop not allowed",
			msg:   mustHex("05010000004254657a6f73205369676e6564204d6573736167653a206d79646170702e636f6d20323032312d30312d31345431353a31363a30345a2048656c6c6f20776f726c6421"),
			policy: signatory.Policy{
				AllowedOperations: []string{"generic", "block", "endorsement"},
				AllowedKinds:      []string{"endorsement", "seed_nonce_revelation", "activate_account", "ballot", "reveal", "origination", "delegation"},
				LogPayloads:       true,
			},
			expected: "request kind `failing_noop' is not allowed",
		},
		{
			title: "failing noop ok",
			msg:   mustHex("05010000004254657a6f73205369676e6564204d6573736167653a206d79646170702e636f6d20323032312d30312d31345431353a31363a30345a2048656c6c6f20776f726c6421"),
			policy: signatory.Policy{
				AllowedOperations: []string{"generic", "block", "endorsement", "failing_noop"},
				AllowedKinds:      []string{"endorsement", "seed_nonce_revelation", "activate_account", "ballot", "reveal", "origination", "delegation"},
				LogPayloads:       true,
			},
		},
		{
			title: "block not allowed",
			msg:   mustHex("019caecab9000753d3029bc7d9a36b60cce68ade985a0a16929587166e0d3de61efff2fa31b7116bf670000000005ee3c23b04519d71c4e54089c56773c44979b3ba3d61078ade40332ad81577ae074f653e0e0000001100000001010000000800000000000753d2da051ba81185783e4cbc633cf2ba809139ef07c3e5f6c5867f930e7667b224430000cde7fbbb948e030000"),
			policy: signatory.Policy{
				AllowedOperations: []string{"generic", "endorsement"},
				AllowedKinds:      []string{"endorsement", "seed_nonce_revelation", "activate_account", "ballot", "reveal", "transaction", "origination", "delegation"},
				LogPayloads:       true,
			},
			expected: "request kind `block' is not allowed",
		},
		{
			title: "endorsement ok",
			msg:   mustHex("029caecab9e3c579180719b76b585cbdf7e440914b8e09fc0e8c64a26b7a4eacd545ad653100000753c3"),
			policy: signatory.Policy{
				AllowedOperations: []string{"generic", "block", "endorsement"},
				AllowedKinds:      []string{"endorsement", "seed_nonce_revelation", "activate_account", "ballot", "reveal", "transaction", "origination", "delegation"},
				LogPayloads:       true,
			},
		},
		{
			title: "endorsement not allowed",
			msg:   mustHex("029caecab9e3c579180719b76b585cbdf7e440914b8e09fc0e8c64a26b7a4eacd545ad653100000753c3"),
			policy: signatory.Policy{
				AllowedOperations: []string{"generic", "block"},
				AllowedKinds:      []string{"endorsement", "seed_nonce_revelation", "activate_account", "ballot", "reveal", "transaction", "origination", "delegation"},
				LogPayloads:       true,
			},
			expected: "request kind `endorsement' is not allowed",
		},
		{
			title: "generic ok",
			msg:   mustHex("019caecab900061de402e27da655a04eaa5dad0647e6ff56d11a5da8efb48c2e90570e27853839e76b68000000005eb576f5047ab08836902391c075dc92640f9d7496faa8cff5b2b24450786d86349b9a528d000000110000000101000000080000000000061de3ad348c90c42bc5b90e89837fdbeb6c1360be7181c9116ef2eb8cb63ebbb1380e00000675d7e0ffa2030000"),
			policy: signatory.Policy{
				AllowedOperations: []string{"generic", "block", "endorsement"},
				AllowedKinds:      []string{"endorsement", "seed_nonce_revelation", "activate_account", "ballot", "reveal", "transaction", "origination", "delegation"},
				LogPayloads:       true,
			},
		},
		{
			title: "generic not allowed",
			msg:   mustHex("03573a2d2d49a3b9634d1605c3aa48ebdd5d21a5885ad17aa44c2b1d0dbcbcac686c004b415314d2b56b0481a3ae8c992ce8bb8dba0369d086039ecb2dc35000c0843d000076b2f1ea1cf6753888ac5488693977446652d79e00"),
			policy: signatory.Policy{
				AllowedOperations: []string{"block", "endorsement"},
				AllowedKinds:      []string{"endorsement", "seed_nonce_revelation", "activate_account", "ballot", "reveal", "origination", "delegation"},
				LogPayloads:       true,
			},
			expected: "request kind `generic' is not allowed",
		},
		{
			title: "delegation ok",
			msg:   mustHex("03b89591b37be370e3db3fc7f77fdd176c5153f75ddcd239094c7ebeb66ee5e8bd6e002ea14368f6494539861ba04cf8cc946ace12cfd4ea09d89f40f44e00ff004b415314d2b56b0481a3ae8c992ce8bb8dba0369"),
			policy: signatory.Policy{
				AllowedOperations: []string{"generic", "block", "endorsement"},
				AllowedKinds:      []string{"endorsement", "seed_nonce_revelation", "activate_account", "ballot", "reveal", "transaction", "origination", "delegation"},
				LogPayloads:       true,
			},
		},
		{
			title: "delegation not allowed",
			msg:   mustHex("03b89591b37be370e3db3fc7f77fdd176c5153f75ddcd239094c7ebeb66ee5e8bd6e002ea14368f6494539861ba04cf8cc946ace12cfd4ea09d89f40f44e00ff004b415314d2b56b0481a3ae8c992ce8bb8dba0369"),
			policy: signatory.Policy{
				AllowedOperations: []string{"generic", "block", "endorsement"},
				AllowedKinds:      []string{"endorsement", "seed_nonce_revelation", "activate_account", "ballot", "reveal", "origination"},
				LogPayloads:       true,
			},
			expected: "operation `delegation' is not allowed",
		},
		{
			title: "origination ok",
			msg:   mustHex("03742d8e0a99049a5053bd71ac18b40fbb1f20e262e45dec88acd6795ba75147066d004b415314d2b56b0481a3ae8c992ce8bb8dba0369d80aa1cb2d8156bb0200000000001c02000000170500035b0501035b050202000000080316053d036d0342000000020000"),
			policy: signatory.Policy{
				AllowedOperations: []string{"generic", "block", "endorsement"},
				AllowedKinds:      []string{"endorsement", "seed_nonce_revelation", "activate_account", "ballot", "reveal", "transaction", "origination", "delegation"},
				LogPayloads:       true,
			},
		},
		{
			title: "origination not allowed",
			msg:   mustHex("03742d8e0a99049a5053bd71ac18b40fbb1f20e262e45dec88acd6795ba75147066d004b415314d2b56b0481a3ae8c992ce8bb8dba0369d80aa1cb2d8156bb0200000000001c02000000170500035b0501035b050202000000080316053d036d0342000000020000"),
			policy: signatory.Policy{
				AllowedOperations: []string{"generic", "block", "endorsement"},
				AllowedKinds:      []string{"endorsement", "seed_nonce_revelation", "activate_account", "ballot", "reveal", "transaction", "delegation"},
				LogPayloads:       true,
			},
			expected: "operation `origination' is not allowed",
		},
		{
			title: "reveal ok",
			msg:   mustHex("03573a2d2d49a3b9634d1605c3aa48ebdd5d21a5885ad17aa44c2b1d0dbcbcac686c004b415314d2b56b0481a3ae8c992ce8bb8dba0369d086039ecb2dc35000c0843d000076b2f1ea1cf6753888ac5488693977446652d79e00"),
			policy: signatory.Policy{
				AllowedOperations: []string{"generic", "block", "endorsement"},
				AllowedKinds:      []string{"endorsement", "seed_nonce_revelation", "activate_account", "ballot", "reveal", "transaction", "origination", "delegation"},
				LogPayloads:       true,
			},
		},
		{
			title: "reveal not allowed",
			msg:   mustHex("0333faca8a156c5e69fc8a63a799911b7c94b126fc7294dbbc0b8cb6880a81944e6b0008460955bf19f2d43ff015d938d53198b14ff637eb09f5ae3f904e000084d813c61c2478b2f30cda0b5593ae5ba293226f44120e42476f0e0941f3702a6e0008460955bf19f2d43ff015d938d53198b14ff6378a09f6ae3ff44e00ff004b415314d2b56b0481a3ae8c992ce8bb8dba0369"),
			policy: signatory.Policy{
				AllowedOperations: []string{"generic", "block", "endorsement"},
				AllowedKinds:      []string{"endorsement", "seed_nonce_revelation", "activate_account", "ballot", "transaction", "origination", "delegation"},
				LogPayloads:       true,
			},
			expected: "operation `reveal' is not allowed",
		},
		{
			title: "transaction ok",
			msg:   mustHex("03573a2d2d49a3b9634d1605c3aa48ebdd5d21a5885ad17aa44c2b1d0dbcbcac686c004b415314d2b56b0481a3ae8c992ce8bb8dba0369d086039ecb2dc35000c0843d000076b2f1ea1cf6753888ac5488693977446652d79e00"),
			policy: signatory.Policy{
				AllowedOperations: []string{"generic", "block", "endorsement"},
				AllowedKinds:      []string{"endorsement", "seed_nonce_revelation", "activate_account", "ballot", "reveal", "transaction", "origination", "delegation"},
				LogPayloads:       true,
			},
		},
		{
			title: "transaction not allowed",
			msg:   mustHex("03573a2d2d49a3b9634d1605c3aa48ebdd5d21a5885ad17aa44c2b1d0dbcbcac686c004b415314d2b56b0481a3ae8c992ce8bb8dba0369d086039ecb2dc35000c0843d000076b2f1ea1cf6753888ac5488693977446652d79e00"),
			policy: signatory.Policy{
				AllowedOperations: []string{"generic", "block", "endorsement"},
				AllowedKinds:      []string{"endorsement", "seed_nonce_revelation", "activate_account", "ballot", "reveal", "origination", "delegation"},
				LogPayloads:       true,
			},
			expected: "operation `transaction' is not allowed",
		},
	}

	priv, err := tezos.ParsePrivateKey(pk, nil)
	require.NoError(t, err)

	pub, err := tezos.EncodePublicKeyHash(priv.Public())
	require.NoError(t, err)

	for _, c := range cases {
		t.Run(c.title, func(t *testing.T) {
			conf := signatory.Config{
				Vaults:    map[string]*config.VaultConfig{"mock": {Driver: "mock"}},
				Watermark: signatory.IgnoreWatermark{},
				VaultFactory: vault.FactoryFunc(func(ctx context.Context, name string, conf *yaml.Node) (vault.Vault, error) {
					return memory.NewUnparsed([]*memory.UnparsedKey{{Data: pk}}, "Mock"), nil
				}),
				Policy: map[string]*signatory.Policy{
					pub: &c.policy,
				},
			}

			s, err := signatory.New(context.Background(), &conf)
			require.NoError(t, err)
			require.NoError(t, s.Unlock(context.Background()))

			_, err = s.Sign(context.Background(), &signatory.SignRequest{PublicKeyHash: pub, Message: c.msg})
			if c.expected != "" {
				require.EqualError(t, err, c.expected)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
