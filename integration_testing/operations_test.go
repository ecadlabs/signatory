package integrationtesting

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"regexp"
	"strings"
	"testing"

	"github.com/ecadlabs/gotez/v2/crypt"
	"github.com/ecadlabs/signatory/integration_testing/tezbox"
	"github.com/ecadlabs/signatory/pkg/config"
	"github.com/ecadlabs/signatory/pkg/hashmap"
	"github.com/ecadlabs/signatory/pkg/server"
	"github.com/ecadlabs/signatory/pkg/signatory"
	"github.com/ecadlabs/signatory/pkg/vault"
	"github.com/ecadlabs/signatory/pkg/vault/memory"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

const (
	signatoryAlias = "signatory"
	contractAlias  = "emit_event"
)

type opTest struct {
	kind        string
	clientArgs  func(alias string) []string
	okMessageRe func(alias string) string
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
		kind: "reveal",
		clientArgs: func(alias string) []string {
			return []string{"reveal", "key", "for", alias}
		},
	},
	{
		kind: "register_global_constant",
		clientArgs: func(alias string) []string {
			return []string{"register", "global", "constant", "999", "from", alias, "--burn-cap", "0.017"}
		},
	},
	{
		kind: "transaction",
		clientArgs: func(alias string) []string {
			return []string{"transfer", "1", "from", alias, "to", "alice", "--burn-cap", "0.06425"}
		},
	},
	{
		kind: "delegation",
		clientArgs: func(alias string) []string {
			return []string{"register", "key", alias, "as", "delegate"}
		},
	},
	{
		kind: "set_deposits_limit",
		clientArgs: func(alias string) []string {
			return []string{"set", "deposits", "limit", "for", alias, "to", "10000"}
		},
	},
	{
		kind: "update_consensus_key",
		clientArgs: func(alias string) []string {
			return []string{"set", "consensus", "key", "for", alias, "to", "bob"}
		},
	},
	{
		kind: "origination",
		clientArgs: func(alias string) []string {
			return []string{"originate", "contract", contractAlias, "transferring", "1", "from", alias, "running", replaceWhiteSpaces(contractBody), "--burn-cap", "0.4"}
		},
	},
	{
		kind: "increase_paid_storage",
		clientArgs: func(alias string) []string {
			return []string{"increase", "the", "paid", "storage", "of", contractAlias, "by", "0x5c", "bytes", "from", alias}
		},
	},
}

func TestOperations(t *testing.T) {
	var k ed25519.PrivateKey
	_, k, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	priv := crypt.Ed25519PrivateKey(k)

	conf := signatory.Config{
		Vaults:    map[string]*config.VaultConfig{"mem": {Driver: "mem"}},
		Watermark: signatory.IgnoreWatermark{},
		VaultFactory: vault.FactoryFunc(func(ctx context.Context, name string, conf *yaml.Node) (vault.Vault, error) {
			return memory.New([]*memory.PrivateKey{{PrivateKey: priv}}, "")
		}),
		Policy: hashmap.NewPublicKeyHashMap([]hashmap.PublicKeyKV[*signatory.PublicKeyPolicy]{{
			Key: priv.Public().Hash(),
			Val: &signatory.PublicKeyPolicy{
				AllowedRequests: requestKinds(),
				AllowedOps:      opKinds(),
				LogPayloads:     true,
			},
		}}),
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
	tezboxConfig.Accounts.Regular[signatoryAlias] = newRemoteSignerConfig(priv.Public(), l.Addr(), regularBalance)

	cont, err := tezbox.Start(tezboxConfig)
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, cont.Stop())
	})

	for _, test := range opTests {
		t.Run(test.kind, func(t *testing.T) {
			a := test.clientArgs(signatoryAlias)
			log.Infof("octez-client arguments: %s", strings.Join(a, " "))
			out, err := cont.Exec("octez-client", test.clientArgs(signatoryAlias)...)
			log.Info(string(out))
			require.NoError(t, err)
			if test.okMessageRe != nil {
				matched, err := regexp.Match(test.okMessageRe(signatoryAlias), out)
				require.NoError(t, err)
				require.True(t, matched)
			}
		})
	}
}
