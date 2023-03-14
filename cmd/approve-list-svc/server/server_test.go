//go:build !integration

package server_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"net"
	"net/http/httptest"
	"testing"

	"github.com/ecadlabs/signatory/cmd/approve-list-svc/server"
	"github.com/ecadlabs/signatory/pkg/auth"
	"github.com/ecadlabs/signatory/pkg/config"
	"github.com/ecadlabs/signatory/pkg/signatory"
	"github.com/ecadlabs/signatory/pkg/utils"
	"github.com/ecadlabs/signatory/pkg/vault"
	"github.com/ecadlabs/signatory/pkg/vault/memory"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func testServer(t *testing.T, addr []net.IP) error {
	// generate hook authentication key
	_, pk, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	srv := server.Server{
		PrivateKey: pk,
		Addresses:  addr,
	}

	handler, err := srv.Handler()
	require.NoError(t, err)

	testSrv := httptest.NewServer(handler)
	defer testSrv.Close()

	hookAuth, err := auth.StaticAuthorizedKeys(pk.Public())
	require.NoError(t, err)

	_, signPk, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	signKeyHash, err := utils.EncodePublicKeyHash(signPk.Public())
	require.NoError(t, err)

	conf := signatory.Config{
		Vaults:    map[string]*config.VaultConfig{"mock": {Driver: "mock"}},
		Watermark: signatory.IgnoreWatermark{},
		VaultFactory: vault.FactoryFunc(func(ctx context.Context, name string, conf *yaml.Node) (vault.Vault, error) {
			return memory.New([]*memory.PrivateKey{
				{
					PrivateKey: signPk,
					KeyID:      signKeyHash,
				},
			}, "Mock")
		}),
		Policy: map[string]*signatory.Policy{
			signKeyHash: nil,
		},
		PolicyHook: &signatory.PolicyHook{
			Address: testSrv.URL,
			Auth:    hookAuth,
		},
	}

	s, err := signatory.New(context.Background(), &conf)
	require.NoError(t, err)

	msg, _ := hex.DecodeString("019caecab9000753d3029bc7d9a36b60cce68ade985a0a16929587166e0d3de61efff2fa31b7116bf670000000005ee3c23b04519d71c4e54089c56773c44979b3ba3d61078ade40332ad81577ae074f653e0e0000001100000001010000000800000000000753d2da051ba81185783e4cbc633cf2ba809139ef07c3e5f6c5867f930e7667b224430000cde7fbbb948e030000")
	_, err = s.Sign(context.Background(), &signatory.SignRequest{PublicKeyHash: signKeyHash, Message: msg, Source: net.IPv6loopback})
	return err
}

func TestServer(t *testing.T) {
	t.Run("Ok", func(t *testing.T) {
		require.NoError(t, testServer(t, []net.IP{net.IPv6loopback}))
	})
	t.Run("Deny", func(t *testing.T) {
		require.EqualError(t, testServer(t, nil), "policy hook: address ::1 is not allowed")
	})
}
