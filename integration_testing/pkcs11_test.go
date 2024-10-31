package integrationtesting

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/ecadlabs/gotez/v2/crypt"
	"github.com/ecadlabs/signatory/integration_testing/tezbox"
	"github.com/ecadlabs/signatory/pkg/config"
	"github.com/ecadlabs/signatory/pkg/hashmap"
	"github.com/ecadlabs/signatory/pkg/server"
	"github.com/ecadlabs/signatory/pkg/signatory"
	"github.com/ecadlabs/signatory/pkg/signatory/watermark"
	"github.com/ecadlabs/signatory/pkg/vault"
	"github.com/ecadlabs/signatory/pkg/vault/pkcs11"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

const (
	libSoftHSMPathUnix = "/usr/lib/softhsm/libsofthsm2.so"
	libSoftHSMPathMac  = "/opt/homebrew/lib/softhsm/libsofthsm2.so"

	userPIN    = "1234"
	soPIN      = "1234"
	keyLabel   = "TestKey"
	tokenLabel = "TestToken"
)

func TestPKCS11(t *testing.T) {
	log.SetLevel(log.DebugLevel)

	// setup SoftHSM
	var path string
	if runtime.GOOS == "darwin" {
		path = libSoftHSMPathMac
	} else {
		path = libSoftHSMPathUnix
	}

	if _, err := os.Stat(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			t.Skipf("libsofthsm2 not installed, skipping testing")
		}
		t.Fatal(err)
	}

	if _, err := exec.LookPath("pkcs11-tool"); err != nil {
		if errors.Is(err, exec.ErrNotFound) {
			t.Skipf("pkcs11-tool not installed, skipping testing")
		}
		t.Fatal(err)
	}

	configPath := filepath.Join(t.TempDir(), "softhsm.conf")
	tokensPath := t.TempDir()

	fd, err := os.OpenFile(configPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
	require.NoError(t, err)
	fmt.Fprintf(fd, "directories.tokendir = %s\n", tokensPath)
	fd.Close()

	t.Setenv("SOFTHSM2_CONF", configPath)

	err = exec.Command("pkcs11-tool", "--verbose", "--module", path, "--init-token", "--label", tokenLabel, "--so-pin", soPIN).Run()
	require.NoError(t, err)

	err = exec.Command("pkcs11-tool", "--verbose", "--module", path, "--login", "--so-pin", soPIN, "--init-pin", "--pin", userPIN).Run()
	require.NoError(t, err)

	err = exec.Command("pkcs11-tool", "--verbose", "--module", path, "--login", "--pin", userPIN, "--keypairgen", "--key-type", "EC:prime256v1", "--usage-sign", "--label", keyLabel).Run()
	require.NoError(t, err)

	v, err := pkcs11.New(context.Background(), &pkcs11.Config{
		LibraryPath: path,
		Pin:         userPIN,
		Label:       keyLabel,
	})
	require.NoError(t, err)
	require.NoError(t, v.Unlock(context.Background()))

	keys, err := vault.Collect(v.ListPublicKeys(context.Background()))
	require.NoError(t, err)
	require.Len(t, keys, 1)
	pub := keys[0].PublicKey().(*crypt.ECDSAPublicKey)
	require.NoError(t, v.Close())

	// Setup Signatory
	conf := signatory.Config{
		Vaults:    map[string]*config.VaultConfig{"pkcs11": {Driver: "pkcs11"}},
		Watermark: watermark.Ignore{},
		VaultFactory: vault.FactoryFunc(func(ctx context.Context, name string, conf *yaml.Node) (vault.Vault, error) {
			return pkcs11.New(context.Background(), &pkcs11.Config{
				LibraryPath: path,
				Pin:         userPIN,
				Label:       keyLabel,
			})
		}),
		Policy: hashmap.NewPublicKeyHashMap([]hashmap.PublicKeyKV[*signatory.PublicKeyPolicy]{
			{
				Key: pub.Hash(),
				Val: &signatory.PublicKeyPolicy{
					AllowedRequests: []string{"generic"},
					AllowedOps:      opKinds(),
					LogPayloads:     true,
				},
			},
		}),
	}
	signer, err := signatory.New(context.Background(), &conf)
	require.NoError(t, err)
	require.NoError(t, signer.Unlock(context.Background()))

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
	tezboxConfig.Accounts.Regular[tz1Alias] = newRemoteSignerConfig(pub, l.Addr(), regularBalance)

	cont, err := tezbox.Start(tezboxConfig)
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, cont.Stop())
	})

	err = cont.ExecLog("octez-client", "transfer", "1", "from", tz1Alias, "to", "alice", "--burn-cap", "0.06425")
	require.NoError(t, err)
}
