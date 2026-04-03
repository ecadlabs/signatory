package server_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ecadlabs/signatory/pkg/server"
	"github.com/stretchr/testify/require"
)

// TestLoginRouteWithoutJWT verifies that the /login route does not panic when
// JWT middleware is not configured. The route is unconditionally registered in
// Handler(), but MidWare can be nil when JWT is disabled. A POST to /login
// must not crash the server.
func TestLoginRouteWithoutJWT(t *testing.T) {
	srv := &server.Server{
		Signer: &signerMock{},
	}

	handler, err := srv.Handler()
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/login", nil)
	req.Header.Set("username", "someone")
	req.Header.Set("password", "something")
	w := httptest.NewRecorder()

	require.NotPanics(t, func() {
		handler.ServeHTTP(w, req)
	})

	// When JWT is disabled, /login should reject or not exist.
	// Accept 401, 404, 405, or 501 as valid non-success responses.
	// A 200/201 would be wrong (should not authenticate without JWT config).
	require.GreaterOrEqual(t, w.Code, 400,
		"login must return a client/server error when JWT is disabled, got %d", w.Code)
}
