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
	"github.com/ecadlabs/signatory/pkg/errors"
	"github.com/ecadlabs/signatory/pkg/hashmap"
	"github.com/ecadlabs/signatory/pkg/signatory"
	"github.com/ecadlabs/signatory/pkg/signatory/watermark"
	"github.com/ecadlabs/signatory/pkg/vault"
	"github.com/ecadlabs/signatory/pkg/vault/memory"
	"github.com/stretchr/testify/require"
	yaml "gopkg.in/yaml.v3"
)

// TestPolicyHookAuthBadPublicKeyHash verifies that callPolicyHook returns an
// error when the hook reply contains an invalid public_key_hash. A malicious
// or buggy hook server could send garbage in that field; the error from
// ParsePublicKeyHash must not be silently dropped.
func TestPolicyHookAuthBadPublicKeyHash(t *testing.T) {
	hookPriv, err := generateKey()
	require.NoError(t, err)

	handler := func(w http.ResponseWriter, r *http.Request) {
		var req signatory.PolicyHookRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			log.Println(err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		// Reply with a deliberately invalid public_key_hash
		replyPl := signatory.PolicyHookReplyPayload{
			Status:        http.StatusOK,
			PublicKeyHash: "not-a-valid-pkh",
			Nonce:         req.Nonce,
		}

		buf, err := json.Marshal(&replyPl)
		if err != nil {
			panic(err)
		}

		sig, err := hookPriv.Sign(buf)
		if err != nil {
			panic(err)
		}

		reply := signatory.PolicyHookReply{
			Payload:   buf,
			Signature: sig.String(),
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(&reply)
	}

	testSrv := httptest.NewServer(http.HandlerFunc(handler))
	defer testSrv.Close()

	hookAuth, err := auth.StaticAuthorizedKeys(hookPriv.Public())
	require.NoError(t, err)

	signPriv, err := generateKey()
	require.NoError(t, err)
	signKeyHash := signPriv.Public().Hash()

	conf := signatory.Config{
		Vaults:    map[string]*config.VaultConfig{"mock": {Driver: "mock"}},
		Watermark: watermark.Ignore{},
		VaultFactory: vault.FactoryFunc(func(context.Context, string, *yaml.Node, config.GlobalContext) (vault.Vault, error) {
			return memory.New([]*memory.PrivateKey{{Key: signPriv}}, "Mock")
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

	// Must return an error from the b58 parse path, not panic.
	require.NotPanics(t, func() {
		_, err = s.Sign(context.Background(), &signatory.SignRequest{PublicKeyHash: signKeyHash, Message: msg})
	})
	require.Error(t, err, "sign must fail when hook reply has invalid public_key_hash")

	// Verify we got the base58 decode error (the dropped-error path), not
	// some unrelated failure.
	require.Contains(t, err.Error(), "base58 decoding error")

	// The error should carry a 403 status since this is an auth failure.
	var httpErr errors.HTTPError
	require.ErrorAs(t, err, &httpErr)
	require.Equal(t, http.StatusForbidden, httpErr.HTTPStatus())
}

// TestPolicyHookAuthBadKeyLookup verifies that callPolicyHook returns an error
// when the hook reply contains a valid but unknown public_key_hash (one that
// is not in the authorized keys store). The error from GetPublicKey must
// propagate, not be silently dropped.
func TestPolicyHookAuthBadKeyLookup(t *testing.T) {
	hookPriv, err := generateKey()
	require.NoError(t, err)

	// Generate a second key that will NOT be in the auth store
	_, unknownPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	unknownKey := crypt.Ed25519PrivateKey(unknownPriv)
	unknownPub := unknownKey.Public()

	handler := func(w http.ResponseWriter, r *http.Request) {
		var req signatory.PolicyHookRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		// Reply claims to be signed by unknownPub (not in auth store)
		replyPl := signatory.PolicyHookReplyPayload{
			Status:        http.StatusOK,
			PublicKeyHash: unknownPub.Hash().String(),
			Nonce:         req.Nonce,
		}

		buf, err := json.Marshal(&replyPl)
		if err != nil {
			panic(err)
		}

		sig, err := hookPriv.Sign(buf)
		if err != nil {
			panic(err)
		}

		reply := signatory.PolicyHookReply{
			Payload:   buf,
			Signature: sig.String(),
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(&reply)
	}

	testSrv := httptest.NewServer(http.HandlerFunc(handler))
	defer testSrv.Close()

	// Auth store only knows about hookPriv's key, not unknownPub
	hookAuth, err := auth.StaticAuthorizedKeys(hookPriv.Public())
	require.NoError(t, err)

	signPriv, err := generateKey()
	require.NoError(t, err)
	signKeyHash := signPriv.Public().Hash()

	conf := signatory.Config{
		Vaults:    map[string]*config.VaultConfig{"mock": {Driver: "mock"}},
		Watermark: watermark.Ignore{},
		VaultFactory: vault.FactoryFunc(func(context.Context, string, *yaml.Node, config.GlobalContext) (vault.Vault, error) {
			return memory.New([]*memory.PrivateKey{{Key: signPriv}}, "Mock")
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

	require.NotPanics(t, func() {
		_, err = s.Sign(context.Background(), &signatory.SignRequest{PublicKeyHash: signKeyHash, Message: msg})
	})
	require.Error(t, err, "sign must fail when hook reply public_key_hash is not in auth store")

	// Verify we got the key-not-found error from the auth store lookup,
	// not some unrelated failure.
	require.ErrorIs(t, err, auth.ErrPublicKeyNotFound)
}
