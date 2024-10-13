package pkcs11

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
	"github.com/ecadlabs/signatory/pkg/vault"
	"github.com/stretchr/testify/require"
)

const (
	libSoftHSMPathUnix = "/usr/lib/softhsm/libsofthsm2.so"
	libSoftHSMPathMac  = "/opt/homebrew/lib/softhsm/libsofthsm2.so"

	userPIN    = "1234"
	soPIN      = "1234"
	keyLabel   = "TestKey"
	tokenLabel = "TestToken"
)

func TestPKCS11Vault(t *testing.T) {
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

	out, err := exec.Command("pkcs11-tool", "--verbose", "--module", path, "--init-token", "--label", tokenLabel, "--so-pin", soPIN).CombinedOutput()
	if err != nil {
		t.Fatal(string(out))
	}

	out, err = exec.Command("pkcs11-tool", "--verbose", "--module", path, "--login", "--so-pin", soPIN, "--init-pin", "--pin", userPIN).CombinedOutput()
	if err != nil {
		t.Fatal(string(out))
	}

	out, err = exec.Command("pkcs11-tool", "--verbose", "--module", path, "--login", "--pin", userPIN, "--keypairgen", "--key-type", "EC:prime256v1", "--usage-sign", "--label", keyLabel).CombinedOutput()
	if err != nil {
		t.Fatal(string(out))
	}

	v, err := New(context.Background(), &Config{
		LibraryPath: path,
		Pin:         userPIN,
		Label:       keyLabel,
	})
	require.NoError(t, err)
	t.Cleanup(func() { v.Close() })

	require.NoError(t, v.Unlock(context.Background()))

	keys, err := vault.Collect(v.ListPublicKeys(context.Background()))
	require.NoError(t, err)
	require.Len(t, keys, 1)
	k0 := keys[0].PublicKey().(*crypt.ECDSAPublicKey)

	key, err := v.GetPublicKey(context.Background(), keys[0].ID())
	require.NoError(t, err)
	k1 := key.PublicKey().(*crypt.ECDSAPublicKey)
	require.Equal(t, k0, k1)
}
