package azure

import (
	"context"
	"crypto"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	tz "github.com/ecadlabs/gotez/v2"
	"github.com/ecadlabs/gotez/v2/crypt"
	"github.com/ecadlabs/signatory/pkg/vault"
	"github.com/stretchr/testify/require"
)

const testECJWK = `{"key":{"kty":"EC","crv":"P-256","x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4","y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"}}`

func overrideWithNonECDSAPublicKey(t *testing.T) {
	var raw tz.Ed25519PublicKey
	raw[0] = 1
	nonECDSA, err := crypt.NewPublicKey(&raw)
	require.NoError(t, err)

	old := newPublicKeyFrom
	newPublicKeyFrom = func(crypto.PublicKey) (crypt.PublicKey, error) {
		return nonECDSA, nil
	}
	t.Cleanup(func() {
		newPublicKeyFrom = old
	})
}

func TestAzureIteratorNextUnsupportedKeyTypeReturnsErrKey(t *testing.T) {
	overrideWithNonECDSAPublicKey(t)

	var baseURL string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/keys":
			fmt.Fprintf(w, `{"value":[{"kid":"%s/keys/test-key"}]}`, baseURL)
		case r.Method == http.MethodGet && r.URL.Path == "/keys/test-key":
			fmt.Fprint(w, testECJWK)
		default:
			http.NotFound(w, r)
		}
	}))
	baseURL = srv.URL
	defer srv.Close()

	v := &Vault{
		client: srv.Client(),
		config: &Config{
			Vault: srv.URL,
		},
	}

	iter := v.List(context.Background())
	_, err := iter.Next()
	require.Error(t, err)
	require.ErrorIs(t, err, vault.ErrKey)
	require.Contains(t, err.Error(), "unsupported key type")

	_, err = iter.Next()
	require.ErrorIs(t, err, vault.ErrDone)
}

func TestAzureImportUnsupportedKeyTypeReturnsError(t *testing.T) {
	overrideWithNonECDSAPublicKey(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut && strings.HasPrefix(r.URL.Path, "/keys/") {
			fmt.Fprint(w, testECJWK)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	v := &Vault{
		client: srv.Client(),
		config: &Config{
			Vault: srv.URL,
		},
	}

	priv, err := crypt.ParsePrivateKey([]byte("spsk1XYsTqUsd7LaLs9a8qpmCvLVJeLEZEXkeAZS5dwcKgUZhv3cYw"))
	require.NoError(t, err)

	var importErr error
	require.NotPanics(t, func() {
		_, importErr = v.Import(context.Background(), priv, nil)
	})
	require.Error(t, importErr)
	require.Contains(t, importErr.Error(), "unsupported key type")
}
