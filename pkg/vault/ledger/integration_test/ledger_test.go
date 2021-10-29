// +build ledger_test

package integrationtest_test

import (
	"context"
	"encoding/hex"
	"os"
	"strconv"
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

const publicKeyHash = "tz1QbkcHhZpzCYwgwHKwS6vvpD1jtteBPvbx"

func TestLedger(t *testing.T) {
	type testCase struct {
		message   string
		signature string
		errMsg    string
	}

	var requests = []*testCase{
		{
			message:   "02ed9d217c1eb156f3fd57a942ee8d53781c849220309d5d2928c64672fd1c87359174e4360000001035",
			signature: "sigdq5b8XzKYpgF8LJbYXx2FhAU1Wy3tJ2vqc9syaJxuXe9KnMsjtaAk7VwRmYppq4cUYyJ8L8bXR4fNuXbMvzrDmpN3RrZV",
		},
		{
			message:   "02ed9d217c1eb156f3fd57a942ee8d53781c849220309d5d2928c64672fd1c87359174e4360000001036", // increment level
			signature: "sigkSZbinpqdnkfZQSfm9a68TDcWpM5HQHMcQwx1KvL3UXwxqfxKgCw1ANRYPw1MwJWYLCRqwZW8t3ZCRoMhkB1UxDfQmrFD",
		},
		{
			message:   "02ed9d217c1eb156f3fd57a942ee8d53781c849220309d5d2928c64672fd1c87359174e4360000001037", // increment level
			signature: "sigfY1xfoRJMjok96XvBU8r9msdvuCHLHnYHJ2h5AJ2gHJRYT3aUfCkeEpzEURUCNC2VqLXK9eXmmC2c9BUQZfZyqiQTYpVR",
		},
		{
			message: "02ed9d217c1eb156f3fd57a942ee8d53781c849220309d5d2928c64672fd1c87359174e4360000001037", // same again level
			errMsg:  "(Ledger/c4c56423): [0x6a80]: Incorrect data",
		},
	}

	setup, _ := strconv.ParseBool(os.Getenv("SETUP_BAKING"))

	if setup {
		pkh, err := ledger.SetupBaking("c4c56423", "bip25519/0'/0'", "", 0, 0)
		require.NoError(t, err)
		require.Equal(t, publicKeyHash, pkh)
	}

	conf := signatory.Config{
		Vaults:    map[string]*config.VaultConfig{"ledger": {Driver: "ledger"}},
		Watermark: signatory.IgnoreWatermark{},
		VaultFactory: vault.FactoryFunc(func(ctx context.Context, name string, conf *yaml.Node) (vault.Vault, error) {
			return ledger.New(context.Background(), &ledger.Config{
				ID:   "c4c56423",
				Keys: []string{"bip25519/0'/0'"},
			})
		}),
		Policy: map[string]*signatory.Policy{
			publicKeyHash: {
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
			PublicKeyHash: publicKeyHash,
			VaultName:     "Ledger",
			ID:            "bip32-ed25519/44'/1729'/0'/0'",
			Policy: &signatory.Policy{
				AllowedOperations: []string{"generic", "block", "endorsement"},
				AllowedKinds:      []string{"endorsement", "seed_nonce_revelation", "activate_account", "ballot", "reveal", "transaction", "origination", "delegation"},
			},
			Active: true,
		},
	}, pub)

	for _, r := range requests {
		msg, _ := hex.DecodeString(r.message)
		req := &signatory.SignRequest{
			PublicKeyHash: publicKeyHash,
			Message:       msg,
		}
		sig, err := signer.Sign(context.Background(), req)

		if r.signature != "" {
			require.NoError(t, err)
			require.Equal(t, r.signature, sig)
		} else {
			require.EqualError(t, err, r.errMsg)
		}
	}
}
