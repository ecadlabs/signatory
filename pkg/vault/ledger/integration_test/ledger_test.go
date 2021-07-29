package integrationtest_test

import (
	"context"
	"encoding/hex"
	"testing"

	"github.com/ecadlabs/signatory/pkg/config"
	"github.com/ecadlabs/signatory/pkg/signatory"
	"github.com/ecadlabs/signatory/pkg/vault"
	"github.com/ecadlabs/signatory/pkg/vault/ledger"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

/*
Use the next recovery phrase:
umbrella idea improve dance correct venue mad atom salmon detail please trip

Expected root PKH:
tz1daTbhMHpmMXQYaVYmzZTM3S11oshHPrMm / c4c56423
*/

func TestLedger(t *testing.T) {
	pkh, err := ledger.SetupBaking("c4c56423", "bip25519/0'/0'", "", 0, 0)
	require.NoError(t, err)
	require.Equal(t, "tz1QbkcHhZpzCYwgwHKwS6vvpD1jtteBPvbx", pkh)

	conf := signatory.Config{
		Vaults:    map[string]*config.VaultConfig{"ledger": {Driver: "ledger"}},
		Watermark: signatory.IgnoreWatermark{},
		VaultFactory: vault.FactoryFunc(func(ctx context.Context, name string, conf *yaml.Node) (vault.Vault, error) {
			return ledger.New(context.Background(), &ledger.Config{
				ID:   "c4c56423",
				Keys: []string{"bip25519/0'/0'", "bip25519/0'/1'"},
			})
		}),
		Policy: map[string]*signatory.Policy{
			"tz1QbkcHhZpzCYwgwHKwS6vvpD1jtteBPvbx": {
				AllowedOperations: []string{"generic", "block", "endorsement"},
				AllowedKinds:      []string{"endorsement", "seed_nonce_revelation", "activate_account", "ballot", "reveal", "transaction", "origination", "delegation"},
			},
			"tz1fKjYB6uXmppMZQFnu459QQkWjMyXm8x8Y": {
				AllowedOperations: []string{"generic", "block", "endorsement"},
				AllowedKinds:      []string{"endorsement", "seed_nonce_revelation", "activate_account", "ballot", "reveal", "transaction", "origination", "delegation"},
			},
		},
	}

	signer, err := signatory.New(context.Background(), &conf)
	require.NoError(t, err)

	pub, err := signer.ListPublicKeys(context.Background())
	require.NoError(t, err)

	require.Equal(t, []*signatory.PublicKey{
		{
			PublicKey:     "edpkv5y3MhiAcQtiAGvJ4DL64zbgXt3QeNJcv3kJ9Wji2deDNoDQZf",
			PublicKeyHash: "tz1QbkcHhZpzCYwgwHKwS6vvpD1jtteBPvbx",
			VaultName:     "Ledger",
			ID:            "bip32-ed25519/44'/1729'/0'/0'",
			Policy: &signatory.Policy{
				AllowedOperations: []string{"generic", "block", "endorsement"},
				AllowedKinds:      []string{"endorsement", "seed_nonce_revelation", "activate_account", "ballot", "reveal", "transaction", "origination", "delegation"},
			},
			Active: true,
		},
		{
			PublicKey:     "edpkttQRdAYshkm7FQTzZpsrViXLuj5ZefeqEGCquuiXVGts6zd4Be",
			PublicKeyHash: "tz1fKjYB6uXmppMZQFnu459QQkWjMyXm8x8Y",
			VaultName:     "Ledger",
			ID:            "bip32-ed25519/44'/1729'/0'/1'",
			Policy: &signatory.Policy{
				AllowedOperations: []string{"generic", "block", "endorsement"},
				AllowedKinds:      []string{"endorsement", "seed_nonce_revelation", "activate_account", "ballot", "reveal", "transaction", "origination", "delegation"},
			},
			Active: true,
		},
	}, pub)

	msg, _ := hex.DecodeString("02ed9d217c1eb156f3fd57a942ee8d53781c849220309d5d2928c64672fd1c87359174e4360000001035")

	req := &signatory.SignRequest{
		PublicKeyHash: "tz1QbkcHhZpzCYwgwHKwS6vvpD1jtteBPvbx",
		Message:       msg,
	}
	sig, err := signer.Sign(context.Background(), req)
	require.NoError(t, err)
	require.Equal(t, "sigdq5b8XzKYpgF8LJbYXx2FhAU1Wy3tJ2vqc9syaJxuXe9KnMsjtaAk7VwRmYppq4cUYyJ8L8bXR4fNuXbMvzrDmpN3RrZV", sig)

	_, err = signer.Sign(context.Background(), req)
	require.EqualError(t, err, "(Ledger/c4c56423): [0x6a80]: Incorrect data") // below water mark
}
