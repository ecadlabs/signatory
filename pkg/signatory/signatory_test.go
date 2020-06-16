package signatory

import (
	"context"
	"crypto"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/ecadlabs/signatory/pkg/config"
	"github.com/ecadlabs/signatory/pkg/cryptoutils"
	"github.com/ecadlabs/signatory/pkg/tezos"
	"github.com/ecadlabs/signatory/pkg/utils"
	"github.com/ecadlabs/signatory/pkg/vault"
	"github.com/segmentio/ksuid"
	"github.com/stretchr/testify/require"
	yaml "gopkg.in/yaml.v3"
)

type noopIterator struct {
	keys []*keyMock
	idx  int
}

func (i *noopIterator) Next() (key vault.StoredKey, err error) {
	if i.idx == len(i.keys) {
		return nil, vault.ErrDone
	}
	key = i.keys[i.idx]
	i.idx++
	return key, nil
}

type vaultMock struct {
	keys map[string]cryptoutils.PrivateKey
}

type keyMock struct {
	id  string
	key crypto.PublicKey
}

func (k *keyMock) PublicKey() crypto.PublicKey { return k.key }
func (k *keyMock) ID() string                  { return k.id }

func (v *vaultMock) GetPublicKey(ctx context.Context, id string) (vault.StoredKey, error) {
	pk, ok := v.keys[id]
	if !ok {
		return nil, ErrVaultNotFound
	}
	return &keyMock{id: id, key: pk.Public()}, nil
}

func (v *vaultMock) ListPublicKeys(ctx context.Context) vault.StoredKeysIterator {
	ret := make([]*keyMock, 0)
	for id, key := range v.keys {
		ret = append(ret, &keyMock{id: id, key: key.Public()})
	}
	return &noopIterator{keys: ret}
}

func (v *vaultMock) Sign(ctx context.Context, digest []byte, key vault.StoredKey) (cryptoutils.Signature, error) {
	return nil, ErrVaultNotFound
}

func (v *vaultMock) Name() string { return "mock" }

func (v *vaultMock) Import(ctx context.Context, pk cryptoutils.PrivateKey, opt utils.Options) (vault.StoredKey, error) {
	id := ksuid.New().String()
	v.keys[id] = pk
	return &keyMock{id: id, key: pk.Public()}, nil
}

var _ vault.Importer = &vaultMock{}

func init() {
	vault.RegisterVault("mock", func(ctx context.Context, node *yaml.Node) (vault.Vault, error) {
		return &vaultMock{keys: make(map[string]cryptoutils.PrivateKey)}, nil
	})
}

func TestSignatory(t *testing.T) {
	conf := Config{
		Vaults:    map[string]*config.VaultConfig{"mock": &config.VaultConfig{Driver: "mock"}},
		Watermark: NewIgnoreWatermark(),
	}

	s, err := NewSignatory(context.Background(), &conf)
	require.NoError(t, err)

	pk := "edsk4FTF78Qf1m2rykGpHqostAiq5gYW4YZEoGUSWBTJr2njsDHSnd"

	imported, err := s.Import(context.Background(), "mock", pk, nil, nil)
	require.NoError(t, err)
	require.Equal(t, "edpkv45regue1bWtuHnCgLU8xWKLwa9qRqv4gimgJKro4LSc3C5VjV", imported.PublicKey)
	require.Equal(t, "tz1LggX2HUdvJ1tF4Fvv8fjsrzLeW4Jr9t2Q", imported.PublicKeyHash)

	list, err := s.ListPublicKeys(context.Background())
	require.NoError(t, err)
	imported.Status = "FOUND_NOT_CONFIGURED"
	require.Equal(t, []*PublicKey{imported}, list)
}

func mustHex(s string) []byte {
	buf, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return buf
}

func TestMatchFilter(t *testing.T) {
	type Param struct {
		msg    []byte
		policy config.TezosPolicy
	}

	type testCase struct {
		input    Param
		expected error
	}

	var cases = []testCase{
		{
			// operation "block"
			input: Param{
				msg: mustHex("019caecab9000753d3029bc7d9a36b60cce68ade985a0a16929587166e0d3de61efff2fa31b7116bf670000000005ee3c23b04519d71c4e54089c56773c44979b3ba3d61078ade40332ad81577ae074f653e0e0000001100000001010000000800000000000753d2da051ba81185783e4cbc633cf2ba809139ef07c3e5f6c5867f930e7667b224430000cde7fbbb948e030000"),
				policy: config.TezosPolicy{
					AllowedOperations: []string{"generic", "block", "endorsement"},
					AllowedKinds:      []string{"endorsement", "seed_nonce_revelation", "activate_account", "ballot", "reveal", "transaction", "origination", "delegation"},
					LogPayloads:       true,
				},
			},
			expected: nil,
		},
		{
			input: Param{
				msg: mustHex("019caecab9000753d3029bc7d9a36b60cce68ade985a0a16929587166e0d3de61efff2fa31b7116bf670000000005ee3c23b04519d71c4e54089c56773c44979b3ba3d61078ade40332ad81577ae074f653e0e0000001100000001010000000800000000000753d2da051ba81185783e4cbc633cf2ba809139ef07c3e5f6c5867f930e7667b224430000cde7fbbb948e030000"),
				policy: config.TezosPolicy{
					AllowedOperations: []string{"generic", "endorsement"},
					AllowedKinds:      []string{"endorsement", "seed_nonce_revelation", "activate_account", "ballot", "reveal", "transaction", "origination", "delegation"},
					LogPayloads:       true,
				},
			},
			expected: fmt.Errorf("request kind `block' is not allowed"),
		},
		// operation "endorsement"
		{
			input: Param{
				msg: mustHex("029caecab9e3c579180719b76b585cbdf7e440914b8e09fc0e8c64a26b7a4eacd545ad653100000753c3"),
				policy: config.TezosPolicy{
					AllowedOperations: []string{"generic", "block", "endorsement"},
					AllowedKinds:      []string{"endorsement", "seed_nonce_revelation", "activate_account", "ballot", "reveal", "transaction", "origination", "delegation"},
					LogPayloads:       true,
				},
			},
			expected: nil,
		},
		{
			input: Param{
				msg: mustHex("029caecab9e3c579180719b76b585cbdf7e440914b8e09fc0e8c64a26b7a4eacd545ad653100000753c3"),
				policy: config.TezosPolicy{
					AllowedOperations: []string{"generic", "block"},
					AllowedKinds:      []string{"endorsement", "seed_nonce_revelation", "activate_account", "ballot", "reveal", "transaction", "origination", "delegation"},
					LogPayloads:       true,
				},
			},
			expected: fmt.Errorf("request kind `endorsement' is not allowed"),
		},
		// operation "generic"
		{
			input: Param{
				msg: mustHex("019caecab900061de402e27da655a04eaa5dad0647e6ff56d11a5da8efb48c2e90570e27853839e76b68000000005eb576f5047ab08836902391c075dc92640f9d7496faa8cff5b2b24450786d86349b9a528d000000110000000101000000080000000000061de3ad348c90c42bc5b90e89837fdbeb6c1360be7181c9116ef2eb8cb63ebbb1380e00000675d7e0ffa2030000"),
				policy: config.TezosPolicy{
					AllowedOperations: []string{"generic", "block", "endorsement"},
					AllowedKinds:      []string{"endorsement", "seed_nonce_revelation", "activate_account", "ballot", "reveal", "transaction", "origination", "delegation"},
					LogPayloads:       true,
				},
			},
			expected: nil,
		},
		{
			input: Param{
				msg: mustHex("03573a2d2d49a3b9634d1605c3aa48ebdd5d21a5885ad17aa44c2b1d0dbcbcac686c004b415314d2b56b0481a3ae8c992ce8bb8dba0369d086039ecb2dc35000c0843d000076b2f1ea1cf6753888ac5488693977446652d79e00"),
				policy: config.TezosPolicy{
					AllowedOperations: []string{"block", "endorsement"},
					AllowedKinds:      []string{"endorsement", "seed_nonce_revelation", "activate_account", "ballot", "reveal", "origination", "delegation"},
					LogPayloads:       true,
				},
			},
			expected: fmt.Errorf("request kind `generic' is not allowed"),
		},
		// kind "delegation"
		{
			input: Param{
				msg: mustHex("03b89591b37be370e3db3fc7f77fdd176c5153f75ddcd239094c7ebeb66ee5e8bd6e002ea14368f6494539861ba04cf8cc946ace12cfd4ea09d89f40f44e00ff004b415314d2b56b0481a3ae8c992ce8bb8dba0369"),
				policy: config.TezosPolicy{
					AllowedOperations: []string{"generic", "block", "endorsement"},
					AllowedKinds:      []string{"endorsement", "seed_nonce_revelation", "activate_account", "ballot", "reveal", "transaction", "origination", "delegation"},
					LogPayloads:       true,
				},
			},
			expected: nil,
		},
		{
			input: Param{
				msg: mustHex("03b89591b37be370e3db3fc7f77fdd176c5153f75ddcd239094c7ebeb66ee5e8bd6e002ea14368f6494539861ba04cf8cc946ace12cfd4ea09d89f40f44e00ff004b415314d2b56b0481a3ae8c992ce8bb8dba0369"),
				policy: config.TezosPolicy{
					AllowedOperations: []string{"generic", "block", "endorsement"},
					AllowedKinds:      []string{"endorsement", "seed_nonce_revelation", "activate_account", "ballot", "reveal", "origination"},
					LogPayloads:       true,
				},
			},
			expected: fmt.Errorf("operation `delegation' is not allowed"),
		},
		// kind "origination"
		{
			input: Param{
				msg: mustHex("03742d8e0a99049a5053bd71ac18b40fbb1f20e262e45dec88acd6795ba75147066d004b415314d2b56b0481a3ae8c992ce8bb8dba0369d80aa1cb2d8156bb0200000000001c02000000170500035b0501035b050202000000080316053d036d0342000000020000"),
				policy: config.TezosPolicy{
					AllowedOperations: []string{"generic", "block", "endorsement"},
					AllowedKinds:      []string{"endorsement", "seed_nonce_revelation", "activate_account", "ballot", "reveal", "transaction", "origination", "delegation"},
					LogPayloads:       true,
				},
			},
			expected: nil,
		},
		{
			input: Param{
				msg: mustHex("03742d8e0a99049a5053bd71ac18b40fbb1f20e262e45dec88acd6795ba75147066d004b415314d2b56b0481a3ae8c992ce8bb8dba0369d80aa1cb2d8156bb0200000000001c02000000170500035b0501035b050202000000080316053d036d0342000000020000"),
				policy: config.TezosPolicy{
					AllowedOperations: []string{"generic", "block", "endorsement"},
					AllowedKinds:      []string{"endorsement", "seed_nonce_revelation", "activate_account", "ballot", "reveal", "transaction", "delegation"},
					LogPayloads:       true,
				},
			},
			expected: fmt.Errorf("operation `origination' is not allowed"),
		},
		// kind "reveal"
		{
			input: Param{
				msg: mustHex("03573a2d2d49a3b9634d1605c3aa48ebdd5d21a5885ad17aa44c2b1d0dbcbcac686c004b415314d2b56b0481a3ae8c992ce8bb8dba0369d086039ecb2dc35000c0843d000076b2f1ea1cf6753888ac5488693977446652d79e00"),
				policy: config.TezosPolicy{
					AllowedOperations: []string{"generic", "block", "endorsement"},
					AllowedKinds:      []string{"endorsement", "seed_nonce_revelation", "activate_account", "ballot", "reveal", "transaction", "origination", "delegation"},
					LogPayloads:       true,
				},
			},
			expected: nil,
		},
		{
			input: Param{
				msg: mustHex("0333faca8a156c5e69fc8a63a799911b7c94b126fc7294dbbc0b8cb6880a81944e6b0008460955bf19f2d43ff015d938d53198b14ff637eb09f5ae3f904e000084d813c61c2478b2f30cda0b5593ae5ba293226f44120e42476f0e0941f3702a6e0008460955bf19f2d43ff015d938d53198b14ff6378a09f6ae3ff44e00ff004b415314d2b56b0481a3ae8c992ce8bb8dba0369"),
				policy: config.TezosPolicy{
					AllowedOperations: []string{"generic", "block", "endorsement"},
					AllowedKinds:      []string{"endorsement", "seed_nonce_revelation", "activate_account", "ballot", "transaction", "origination", "delegation"},
					LogPayloads:       true,
				},
			},
			expected: fmt.Errorf("operation `reveal' is not allowed"),
		},
		// kind "transaction"
		{
			input: Param{
				msg: mustHex("03573a2d2d49a3b9634d1605c3aa48ebdd5d21a5885ad17aa44c2b1d0dbcbcac686c004b415314d2b56b0481a3ae8c992ce8bb8dba0369d086039ecb2dc35000c0843d000076b2f1ea1cf6753888ac5488693977446652d79e00"),
				policy: config.TezosPolicy{
					AllowedOperations: []string{"generic", "block", "endorsement"},
					AllowedKinds:      []string{"endorsement", "seed_nonce_revelation", "activate_account", "ballot", "reveal", "transaction", "origination", "delegation"},
					LogPayloads:       true,
				},
			},
			expected: nil,
		},
		{
			input: Param{
				msg: mustHex("03573a2d2d49a3b9634d1605c3aa48ebdd5d21a5885ad17aa44c2b1d0dbcbcac686c004b415314d2b56b0481a3ae8c992ce8bb8dba0369d086039ecb2dc35000c0843d000076b2f1ea1cf6753888ac5488693977446652d79e00"),
				policy: config.TezosPolicy{
					AllowedOperations: []string{"generic", "block", "endorsement"},
					AllowedKinds:      []string{"endorsement", "seed_nonce_revelation", "activate_account", "ballot", "reveal", "origination", "delegation"},
					LogPayloads:       true,
				},
			},
			expected: fmt.Errorf("operation `transaction' is not allowed"),
		},
	}

	conf := Config{
		Vaults:    map[string]*config.VaultConfig{"mock": &config.VaultConfig{Driver: "mock"}},
		Watermark: NewIgnoreWatermark(),
	}

	s, err := NewSignatory(context.Background(), &conf)
	require.NoError(t, err)

	for _, test := range cases {
		msg, err := tezos.ParseUnsignedMessage(test.input.msg)
		require.NoError(t, err)
		got := s.matchFilter(msg, &test.input.policy)
		require.Equal(t, test.expected, got)
	}

}
