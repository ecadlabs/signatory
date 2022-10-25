//go:build integration

package integrationtest

import (
	"context"
	"crypto/ed25519"
	"crypto/sha512"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"

	log "github.com/sirupsen/logrus"

	"github.com/ecadlabs/signatory/pkg/auth"
	"github.com/ecadlabs/signatory/pkg/config"
	"github.com/ecadlabs/signatory/pkg/cryptoutils"
	"github.com/ecadlabs/signatory/pkg/server"
	"github.com/ecadlabs/signatory/pkg/signatory"
	"github.com/ecadlabs/signatory/pkg/tezos"
	"github.com/ecadlabs/signatory/pkg/vault"
	"github.com/ecadlabs/signatory/pkg/vault/memory"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/pbkdf2"
	"gopkg.in/yaml.v3"
)

const (
	userName       = "signatory-integration-test"      // Key name for transactions
	authKeyName    = "signatory-integration-test-auth" // Key name to authenticate requests to the signer
	envKey         = "ENV_SECRET_KEY"                  // Activated secret key to sign operations in Base58 format
	envKeyJSON     = "ENV_ACTIVATION_KEY"              // (alternatively) JSON key file used to activate a funded account
	envNodeAddress = "ENV_NODE_ADDR"                   // Testnet node address
	listenAddr     = "localhost:6732"
)

type secretKeyJSON struct {
	Mnemonic []string `json:"mnemonic"`
	Secret   string   `json:"secret"`
	Amount   string   `json:"amount"`
	PKH      string   `json:"pkh"`
	Password string   `json:"password"`
	Email    string   `json:"email"`
}

func secretKeyFromEnv() (cryptoutils.PrivateKey, error) {
	if s := os.Getenv(envKey); s != "" {
		return tezos.ParsePrivateKey(s, nil)
	}

	if s := os.Getenv(envKeyJSON); s != "" {
		var data secretKeyJSON
		if err := json.Unmarshal([]byte(s), &data); err != nil {
			return nil, err
		}

		if len(data.Mnemonic) != 0 && data.Password != "" && data.Email != "" && data.PKH != "" {
			mnemonic := strings.Join(data.Mnemonic, " ")
			salt := "mnemonic" + data.Email + data.Password
			k := pbkdf2.Key([]byte(mnemonic), []byte(salt), 2048, 64, sha512.New)
			pk := ed25519.NewKeyFromSeed(k[:32])
			pkh, err := tezos.EncodePublicKeyHash(pk.Public())
			if err != nil {
				return nil, err
			}
			if data.PKH != pkh {
				return nil, errors.New("public key hash mismatch")
			}
			return pk, nil
		}
	}

	return nil, errors.New("secret key is required")
}

// Signatory wrapper to keep Sign calls arguments and returned data
type signCall struct {
	request   *signatory.SignRequest
	signature string
	err       error
}

type signerWrapper struct {
	*signatory.Signatory
	calls []*signCall
	mtx   sync.Mutex
}

func (s *signerWrapper) Sign(ctx context.Context, req *signatory.SignRequest) (string, error) {
	signature, err := s.Signatory.Sign(ctx, req)
	s.mtx.Lock()
	s.calls = append(s.calls, &signCall{request: req, signature: signature, err: err})
	s.mtx.Unlock()
	return signature, err
}

func (s *signerWrapper) signCalls() []*signCall {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	return s.calls
}

// Generate authentication key
func genAuthKey() (pub, pkh, priv string, err error) {
	pubk, privk, err := ed25519.GenerateKey(nil)
	if err != nil {
		return
	}
	if pub, err = tezos.EncodePublicKey(pubk); err != nil {
		return
	}
	if priv, err = tezos.EncodePrivateKey(privk); err != nil {
		return
	}
	if pkh, err = tezos.EncodePublicKeyHash(pubk); err != nil {
		return
	}
	return
}

func logExec(t *testing.T, name string, arg ...string) error {
	buf, err := exec.Command(name, arg...).CombinedOutput()
	t.Log(string(buf))
	return err
}

func TestSignatory(t *testing.T) {
	pk, err := secretKeyFromEnv()
	require.NoError(t, err)

	pub, err := tezos.EncodePublicKeyHash(pk.Public())
	require.NoError(t, err)

	authPub, authPKH, authPriv, err := genAuthKey()
	require.NoError(t, err)

	// setup Signatory instance
	conf := signatory.Config{
		Vaults:    map[string]*config.VaultConfig{"mem": {Driver: "mem"}},
		Watermark: signatory.IgnoreWatermark{},
		VaultFactory: vault.FactoryFunc(func(ctx context.Context, name string, conf *yaml.Node) (vault.Vault, error) {
			return memory.New([]*memory.PrivateKey{{PrivateKey: pk}}, "")
		}),
		Policy: map[string]*signatory.Policy{
			pub: {
				AllowedRequests: []string{"generic", "block", "endorsement"},
				AllowedOps:      []string{"endorsement", "seed_nonce_revelation", "activate_account", "ballot", "reveal", "transaction", "origination", "delegation"},
			},
		},
	}

	s, err := signatory.New(context.Background(), &conf)
	require.NoError(t, err)
	signer := signerWrapper{Signatory: s}

	require.NoError(t, signer.Unlock(context.Background()))

	srvCfg := server.Server{
		Signer:  &signer,
		Address: listenAddr,
		Auth:    auth.Must(auth.StaticAuthorizedKeysFromString(authPub)),
	}

	srv, err := srvCfg.New()
	require.NoError(t, err)
	log.Printf("HTTP server is listening for connections on %s", srv.Addr)
	go srv.ListenAndServe()

	epAddr := os.Getenv(envNodeAddress)
	require.NotEmpty(t, epAddr)

	t.Run("Auth", func(t *testing.T) {
		dir := "./authenticated-tezos-client"
		os.Mkdir(dir, 0777)
		// initialize client
		require.NoError(t, logExec(t, "tezos-client", "--base-dir", dir, "--endpoint", epAddr, "config", "init"))
		// import key
		require.NoError(t, logExec(t, "tezos-client", "--base-dir", dir, "import", "secret", "key", userName, "http://"+srv.Addr+"/"+pub))
		// add authentication key
		require.NoError(t, logExec(t, "tezos-client", "--base-dir", dir, "import", "secret", "key", authKeyName, "unencrypted:"+authPriv))
		// create transaction
		require.NoError(t, logExec(t, "tezos-client", "--base-dir", dir, "transfer", "0.01", "from", userName, "to", "tz1burnburnburnburnburnburnburjAYjjX", "--burn-cap", "0.06425"))
	})

	t.Run("NoAuth", func(t *testing.T) {
		dir := "./unauthenticated-tezos-client"
		os.Mkdir(dir, 0777)
		// initialize client
		require.NoError(t, logExec(t, "tezos-client", "--base-dir", dir, "--endpoint", epAddr, "config", "init"))
		// import key
		require.NoError(t, logExec(t, "tezos-client", "--base-dir", dir, "import", "secret", "key", userName, "http://"+srv.Addr+"/"+pub))
		// create transaction
		require.Error(t, logExec(t, "tezos-client", "--base-dir", dir, "transfer", "0.01", "from", userName, "to", "tz1burnburnburnburnburnburnburjAYjjX", "--burn-cap", "0.06425"))
	})

	srv.Shutdown(context.Background())

	calls := signer.signCalls()
	require.Equal(t, 1, len(calls))
	require.Equal(t, authPKH, calls[0].request.ClientPublicKeyHash)
}
