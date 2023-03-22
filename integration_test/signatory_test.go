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
	"github.com/ecadlabs/signatory/pkg/crypt"
	"github.com/ecadlabs/signatory/pkg/hashmap"
	"github.com/ecadlabs/signatory/pkg/server"
	"github.com/ecadlabs/signatory/pkg/signatory"
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

func secretKeyFromEnv() (crypt.PrivateKey, error) {
	if s := os.Getenv(envKey); s != "" {
		priv, err := crypt.ParsePrivateKey([]byte(s))
		if err != nil {
			return nil, err
		}
		return priv, nil
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
			priv := crypt.Ed25519PrivateKey(ed25519.NewKeyFromSeed(k[:32]))
			pkh := priv.Public().Hash()
			if data.PKH != pkh.String() {
				return nil, errors.New("public key hash mismatch")
			}
			return priv, nil
		}
	}

	return nil, errors.New("secret key is required")
}

// Signatory wrapper to keep Sign calls arguments and returned data
type signCall struct {
	request   *signatory.SignRequest
	signature crypt.Signature
	err       error
}

type signerWrapper struct {
	*signatory.Signatory
	calls []*signCall
	mtx   sync.Mutex
}

func (s *signerWrapper) Sign(ctx context.Context, req *signatory.SignRequest) (crypt.Signature, error) {
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
func genAuthKey() (crypt.PublicKey, crypt.PrivateKey, error) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, nil, err
	}
	return crypt.Ed25519PublicKey(pub), crypt.Ed25519PrivateKey(priv), nil
}

func logExec(t *testing.T, name string, arg ...string) error {
	buf, err := exec.Command(name, arg...).CombinedOutput()
	t.Log(string(buf))
	return err
}

func TestSignatory(t *testing.T) {
	priv, err := secretKeyFromEnv()
	require.NoError(t, err)
	pub := priv.Public()

	authPub, authPriv, err := genAuthKey()
	require.NoError(t, err)

	// setup Signatory instance
	conf := signatory.Config{
		Vaults:    map[string]*config.VaultConfig{"mem": {Driver: "mem"}},
		Watermark: signatory.IgnoreWatermark{},
		VaultFactory: vault.FactoryFunc(func(ctx context.Context, name string, conf *yaml.Node) (vault.Vault, error) {
			return memory.New([]*memory.PrivateKey{{PrivateKey: priv}}, "")
		}),
		Policy: hashmap.NewPublicKeyHashMap([]hashmap.PublicKeyKV[*signatory.PublicKeyPolicy]{
			{
				Key: pub.Hash(),
				Val: &signatory.PublicKeyPolicy{
					AllowedRequests: []string{"generic", "block", "endorsement"},
					AllowedOps:      []string{"endorsement", "seed_nonce_revelation", "activate_account", "ballot", "reveal", "transaction", "origination", "delegation"},
				},
			},
		}),
	}

	s, err := signatory.New(context.Background(), &conf)
	require.NoError(t, err)
	signer := signerWrapper{Signatory: s}

	require.NoError(t, signer.Unlock(context.Background()))

	srvCfg := server.Server{
		Signer:  &signer,
		Address: listenAddr,
		Auth:    auth.Must(auth.StaticAuthorizedKeys(authPub)),
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
		require.NoError(t, logExec(t, "octez-client", "--base-dir", dir, "--endpoint", epAddr, "config", "init"))
		// import key
		require.NoError(t, logExec(t, "octez-client", "--base-dir", dir, "import", "secret", "key", userName, "http://"+srv.Addr+"/"+pub.Hash().String()))
		// add authentication key
		require.NoError(t, logExec(t, "octez-client", "--base-dir", dir, "import", "secret", "key", authKeyName, "unencrypted:"+authPriv.String()))
		// create transaction
		require.NoError(t, logExec(t, "octez-client", "--base-dir", dir, "transfer", "0.01", "from", userName, "to", "tz1burnburnburnburnburnburnburjAYjjX", "--burn-cap", "0.06425"))
	})

	t.Run("NoAuth", func(t *testing.T) {
		dir := "./unauthenticated-tezos-client"
		os.Mkdir(dir, 0777)
		// initialize client
		require.NoError(t, logExec(t, "octez-client", "--base-dir", dir, "--endpoint", epAddr, "config", "init"))
		// import key
		require.NoError(t, logExec(t, "octez-client", "--base-dir", dir, "import", "secret", "key", userName, "http://"+srv.Addr+"/"+pub.Hash().String()))
		// create transaction
		require.Error(t, logExec(t, "octez-client", "--base-dir", dir, "transfer", "0.01", "from", userName, "to", "tz1burnburnburnburnburnburnburjAYjjX", "--burn-cap", "0.06425"))
	})

	srv.Shutdown(context.Background())

	calls := signer.signCalls()
	require.Equal(t, 1, len(calls))
	require.Equal(t, authPub.Hash(), calls[0].request.ClientPublicKeyHash)
}
