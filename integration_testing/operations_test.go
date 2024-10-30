package integrationtesting

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"regexp"
	"strings"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/ecadlabs/gotez/v2/crypt"
	"github.com/ecadlabs/signatory/integration_testing/tezbox"
	"github.com/ecadlabs/signatory/pkg/config"
	"github.com/ecadlabs/signatory/pkg/hashmap"
	"github.com/ecadlabs/signatory/pkg/server"
	"github.com/ecadlabs/signatory/pkg/signatory"
	"github.com/ecadlabs/signatory/pkg/signatory/watermark"
	"github.com/ecadlabs/signatory/pkg/vault"
	"github.com/ecadlabs/signatory/pkg/vault/memory"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

const (
	tz1Alias      = "signatory_tz1"
	tz2Alias      = "signatory_tz2"
	tz3Alias      = "signatory_tz3"
	bakerAlias    = "signatory_baker"
	contractAlias = "emit_event"
)

type opTest struct {
	name        string
	clientArgs  []string
	okMessageRe string
}

const contractBody = `{
	parameter unit;
	storage unit;
	code {
		DROP;
		UNIT;
		PUSH nat 10;
		LEFT string;
		EMIT %event;
		PUSH string "lorem ipsum";
		RIGHT nat;
		EMIT %event (or (nat %number) (string %words));
		NIL operation;
		SWAP;
		CONS;
		SWAP;
		CONS;
		PAIR
	}
}
`

func replaceWhiteSpaces(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '\n' || r == '\t' {
			return ' '
		}
		return r
	}, s)
}

var opTests = []*opTest{
	{
		name:       "reveal",
		clientArgs: []string{"reveal", "key", "for", tz1Alias},
	},
	{
		name:       "register_global_constant",
		clientArgs: []string{"register", "global", "constant", "999", "from", tz1Alias, "--burn-cap", "0.017"},
	},
	{
		name:       "transaction-tz1",
		clientArgs: []string{"transfer", "1", "from", tz1Alias, "to", "alice", "--burn-cap", "0.06425"},
	},
	{
		name:       "transaction-tz2",
		clientArgs: []string{"transfer", "1", "from", tz2Alias, "to", "alice", "--burn-cap", "0.06425"},
	},
	{
		name:       "transaction-tz3",
		clientArgs: []string{"transfer", "1", "from", tz3Alias, "to", "alice", "--burn-cap", "0.06425"},
	},
	{
		name:       "delegation",
		clientArgs: []string{"register", "key", tz1Alias, "as", "delegate"},
	},
	{
		name:       "set_deposits_limit",
		clientArgs: []string{"set", "deposits", "limit", "for", tz1Alias, "to", "10000"},
	},
	{
		name:       "update_consensus_key",
		clientArgs: []string{"set", "consensus", "key", "for", tz1Alias, "to", "bob"},
	},
	{
		name:       "origination",
		clientArgs: []string{"originate", "contract", contractAlias, "transferring", "1", "from", tz1Alias, "running", replaceWhiteSpaces(contractBody), "--burn-cap", "0.4"},
	},
	{
		name:       "increase_paid_storage",
		clientArgs: []string{"increase", "the", "paid", "storage", "of", contractAlias, "by", "0x5c", "bytes", "from", tz1Alias},
	},
}

func genEd25519Keys(n int) ([]crypt.Ed25519PrivateKey, error) {
	out := make([]crypt.Ed25519PrivateKey, n)
	for i := 0; i < n; i++ {
		_, k, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		out[i] = crypt.Ed25519PrivateKey(k)
	}
	return out, nil
}

func TestOperations(t *testing.T) {
	priv1, err := genEd25519Keys(2)
	require.NoError(t, err)

	k2, err := ecdsa.GenerateKey(secp256k1.S256(), rand.Reader)
	require.NoError(t, err)
	priv2 := (*crypt.ECDSAPrivateKey)(k2)

	k3, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	priv3 := (*crypt.ECDSAPrivateKey)(k3)

	conf := signatory.Config{
		Vaults:    map[string]*config.VaultConfig{"mem": {Driver: "mem"}},
		Watermark: watermark.Ignore{},
		VaultFactory: vault.FactoryFunc(func(ctx context.Context, name string, conf *yaml.Node) (vault.Vault, error) {
			return memory.New([]*memory.PrivateKey{
				{PrivateKey: priv1[0]},
				{PrivateKey: priv1[1]},
				{PrivateKey: priv2},
				{PrivateKey: priv3},
			}, "")
		}),
		Policy: hashmap.NewPublicKeyHashMap([]hashmap.PublicKeyKV[*signatory.PublicKeyPolicy]{
			{
				Key: priv1[0].Public().Hash(),
				Val: &signatory.PublicKeyPolicy{
					AllowedRequests: []string{"generic"},
					AllowedOps:      opKinds(),
					LogPayloads:     true,
				},
			},
			{
				Key: priv2.Public().Hash(),
				Val: &signatory.PublicKeyPolicy{
					AllowedRequests: []string{"generic"},
					AllowedOps:      opKinds(),
					LogPayloads:     true,
				},
			},
			{
				Key: priv3.Public().Hash(),
				Val: &signatory.PublicKeyPolicy{
					AllowedRequests: []string{"generic"},
					AllowedOps:      opKinds(),
					LogPayloads:     true,
				},
			},
			{
				Key: priv1[1].Public().Hash(),
				Val: &signatory.PublicKeyPolicy{
					AllowedRequests: []string{"block", "attestation", "preattestation", "generic"},
					AllowedOps:      opKinds(),
					LogPayloads:     true,
				},
			},
		}),
	}
	signer, err := signatory.New(context.Background(), &conf)
	require.NoError(t, err)

	srv := &server.Server{
		Signer:  signer,
		Address: ":0", // choose random
	}

	httpServer, err := srv.New()
	require.NoError(t, err)
	l, err := startHTTPServer(httpServer)
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, httpServer.Shutdown(context.Background()))
	})

	tezboxConfig, err := genBaseConfig()
	require.NoError(t, err)

	tezboxConfig.Accounts.Regular[tz1Alias] = newRemoteSignerConfig(priv1[0].Public(), l.Addr(), regularBalance)
	tezboxConfig.Accounts.Regular[tz2Alias] = newRemoteSignerConfig(priv2.Public(), l.Addr(), regularBalance)
	tezboxConfig.Accounts.Regular[tz3Alias] = newRemoteSignerConfig(priv3.Public(), l.Addr(), regularBalance)

	tezboxConfig.Accounts.Bakers = tezbox.Accounts{
		bakerAlias: newRemoteSignerConfig(priv1[1].Public(), l.Addr(), bakerBalance),
	}

	cont, err := tezbox.Start(tezboxConfig)
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, cont.Stop())
	})

	for _, test := range opTests {
		t.Run(test.name, func(t *testing.T) {
			log.Infof("octez-client arguments: %s", strings.Join(test.clientArgs, " "))
			out, err := cont.Exec("octez-client", test.clientArgs...)
			log.Info(string(out))
			require.NoError(t, err)
			if test.okMessageRe != "" {
				matched, err := regexp.Match(test.okMessageRe, out)
				require.NoError(t, err)
				require.True(t, matched)
			}
		})
	}
}
