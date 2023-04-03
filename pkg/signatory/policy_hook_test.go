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

	"github.com/ecadlabs/signatory/pkg/auth"
	"github.com/ecadlabs/signatory/pkg/config"
	"github.com/ecadlabs/signatory/pkg/crypt"
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
		VaultFactory: vault.FactoryFunc(func(ctx context.Context, name string, conf *yaml.Node) (vault.Vault, error) {
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

	msg := mustHex("019caecab9000753d3029bc7d9a36b60cce68ade985a0a16929587166e0d3de61efff2fa31b7116bf670000000005ee3c23b04519d71c4e54089c56773c44979b3ba3d61078ade40332ad81577ae074f653e0e0000001100000001010000000800000000000753d2da051ba81185783e4cbc633cf2ba809139ef07c3e5f6c5867f930e7667b224430000cde7fbbb948e030000")
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
		VaultFactory: vault.FactoryFunc(func(ctx context.Context, name string, conf *yaml.Node) (vault.Vault, error) {
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

	msg := mustHex("019caecab9000753d3029bc7d9a36b60cce68ade985a0a16929587166e0d3de61efff2fa31b7116bf670000000005ee3c23b04519d71c4e54089c56773c44979b3ba3d61078ade40332ad81577ae074f653e0e0000001100000001010000000800000000000753d2da051ba81185783e4cbc633cf2ba809139ef07c3e5f6c5867f930e7667b224430000cde7fbbb948e030000")
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
