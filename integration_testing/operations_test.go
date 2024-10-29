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

const signatoryAlias = "signatory"

type opTest struct {
	kind        string
	clientArgs  func(kind, alias string) []string
	okMessageRe func(kind, alias string) string
}

var opTests = []*opTest{
	{
		kind: "transaction",
		clientArgs: func(kind, alias string) []string {
			return []string{"transfer", "1", "from", alias, "to", "alice", "--burn-cap", "0.06425"}
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
			a := test.clientArgs(test.kind, signatoryAlias)
			log.Infof("octez-client arguments: %s", strings.Join(a, " "))
			out, err := cont.Exec("octez-client", test.clientArgs(test.kind, signatoryAlias)...)
			log.Info(string(out))
			require.NoError(t, err)
			if test.okMessageRe != nil {
				matched, err := regexp.Match(test.okMessageRe(test.kind, signatoryAlias), out)
				require.NoError(t, err)
				require.True(t, matched)
			}
		})
	}
}
