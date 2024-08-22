//go:build !integration

package signatory_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ecadlabs/gotez/v2/crypt"
	"github.com/ecadlabs/signatory/pkg/auth"
	"github.com/ecadlabs/signatory/pkg/config"
	"github.com/ecadlabs/signatory/pkg/hashmap"
	"github.com/ecadlabs/signatory/pkg/signatory"
	"github.com/ecadlabs/signatory/pkg/vault"
	"github.com/ecadlabs/signatory/pkg/vault/memory"
	"github.com/stretchr/testify/require"
	yaml "gopkg.in/yaml.v3"
)

func generateKey() (crypt.PrivateKey, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return crypt.Ed25519PrivateKey(priv), nil
}

func serveHookAuth(status int, priv crypt.PrivateKey) (func(w http.ResponseWriter, r *http.Request), error) {
	pub := priv.Public()
	return func(w http.ResponseWriter, r *http.Request) {
		var req signatory.PolicyHookRequest
		dec := json.NewDecoder(r.Body)
		if err := dec.Decode(&req); err != nil {
			log.Println(err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		replyPl := signatory.PolicyHookReplyPayload{
			Status:        status,
			PublicKeyHash: pub.Hash().String(),
			Nonce:         req.Nonce,
		}

		buf, err := json.Marshal(&replyPl)
		if err != nil {
			log.Println(err)
			panic(err)
		}

		sig, err := priv.Sign(buf)
		if err != nil {
			log.Println(err)
			panic(err)
		}

		reply := signatory.PolicyHookReply{
			Payload:   buf,
			Signature: sig.String(),
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		json.NewEncoder(w).Encode(&reply)
	}, nil
}

func serveHook(status int) (func(w http.ResponseWriter, r *http.Request), error) {
	return func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
	}, nil
}

func testPolicyHookAuth(t *testing.T, status int) error {
	// generate hook authentication key
	hookPriv, err := generateKey()
	require.NoError(t, err)

	handler, err := serveHookAuth(status, hookPriv)
	require.NoError(t, err)

	testSrv := httptest.NewServer(http.HandlerFunc(handler))
	defer testSrv.Close()

	hookAuth, err := auth.StaticAuthorizedKeys(hookPriv.Public())
	require.NoError(t, err)

	signPriv, err := generateKey()
	require.NoError(t, err)

	signPub := signPriv.Public()
	signKeyHash := signPub.Hash()

	conf := signatory.Config{
		Vaults:    map[string]*config.VaultConfig{"mock": {Driver: "mock"}},
		Watermark: signatory.IgnoreWatermark{},
		VaultFactory: vault.FactoryFunc(func(ctx context.Context, name string, conf *yaml.Node, g config.GlobalContext) (vault.Vault, error) {
			return memory.New([]*memory.PrivateKey{
				{
					PrivateKey: signPriv,
					KeyID:      signKeyHash.String(),
				},
			}, "Mock")
		}),
		Policy: hashmap.NewPublicKeyHashMap([]hashmap.PublicKeyKV[*signatory.PublicKeyPolicy]{{Key: signKeyHash, Val: nil}}),

		PolicyHook: &signatory.PolicyHook{
			Address: testSrv.URL,
			Auth:    hookAuth,
		},
	}

	s, err := signatory.New(context.Background(), &conf)
	require.NoError(t, err)

	msg := mustHex("11ed9d217c0000518e0118425847ac255b6d7c30ce8fec23b8eaf13b741de7d18509ac2ef83c741209630000000061947af504805682ea5d089837764b3efcc90b91db24294ff9ddb66019f332ccba17cc4741000000210000000102000000040000518e0000000000000004ffffffff0000000400000000eb1320a71e8bf8b0162a3ec315461e9153a38b70d00d5dde2df85eb92748f8d068d776e356683a9e23c186ccfb72ddc6c9857bb1704487972922e7c89a7121f800000000a8e1dd3c000000000000")
	_, err = s.Sign(context.Background(), &signatory.SignRequest{PublicKeyHash: signKeyHash, Message: msg})
	return err
}

func testPolicyHook(t *testing.T, status int) error {
	// generate hook authentication key
	handler, err := serveHook(status)
	require.NoError(t, err)

	testSrv := httptest.NewServer(http.HandlerFunc(handler))
	defer testSrv.Close()

	signPriv, err := generateKey()
	require.NoError(t, err)
	signKeyHash := signPriv.Public().Hash()

	conf := signatory.Config{
		Vaults:    map[string]*config.VaultConfig{"mock": {Driver: "mock"}},
		Watermark: signatory.IgnoreWatermark{},
		VaultFactory: vault.FactoryFunc(func(ctx context.Context, name string, conf *yaml.Node, g config.GlobalContext) (vault.Vault, error) {
			return memory.New([]*memory.PrivateKey{
				{
					PrivateKey: signPriv,
					KeyID:      signKeyHash.String(),
				},
			}, "Mock")
		}),
		Policy: hashmap.NewPublicKeyHashMap([]hashmap.PublicKeyKV[*signatory.PublicKeyPolicy]{{Key: signKeyHash, Val: nil}}),
		PolicyHook: &signatory.PolicyHook{
			Address: testSrv.URL,
		},
	}

	s, err := signatory.New(context.Background(), &conf)
	require.NoError(t, err)

	msg := mustHex("11ed9d217c0000518e0118425847ac255b6d7c30ce8fec23b8eaf13b741de7d18509ac2ef83c741209630000000061947af504805682ea5d089837764b3efcc90b91db24294ff9ddb66019f332ccba17cc4741000000210000000102000000040000518e0000000000000004ffffffff0000000400000000eb1320a71e8bf8b0162a3ec315461e9153a38b70d00d5dde2df85eb92748f8d068d776e356683a9e23c186ccfb72ddc6c9857bb1704487972922e7c89a7121f800000000a8e1dd3c000000000000")
	_, err = s.Sign(context.Background(), &signatory.SignRequest{PublicKeyHash: signKeyHash, Message: msg})
	return err
}

func TestPolicyHookAuth(t *testing.T) {
	t.Run("Ok", func(t *testing.T) {
		require.NoError(t, testPolicyHookAuth(t, http.StatusOK))
	})
	t.Run("Deny", func(t *testing.T) {
		require.EqualError(t, testPolicyHookAuth(t, http.StatusForbidden), "policy hook: 403 Forbidden")
	})
}

func TestPolicyHook(t *testing.T) {
	t.Run("Ok", func(t *testing.T) {
		require.NoError(t, testPolicyHook(t, http.StatusOK))
	})
	t.Run("Deny", func(t *testing.T) {
		require.EqualError(t, testPolicyHook(t, http.StatusForbidden), "policy hook: 403 Forbidden")
	})
}
