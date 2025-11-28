package server_test

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	integrationtest "github.com/ecadlabs/signatory/integration_test/tests"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test configuration constants
const (
	baseURL  = "http://localhost:6732/"
	secret   = "!sEtcU5RwLQYsA5qQ1c6zpo3FljQxfAKP"
	secret2  = "*sEtcU5RwLQYsA5qQ1c6zpo3FljQxfAKP"
	loginURL = baseURL + "login"
	message  = "\"03c8e312c61a5fd8e9d6ff1d5dccf900e10b5769e55738eb365e99636e3c3fd1d76c006b82198cb179e8306c1bedd08f12dc863f328886df0202e90700c0843d0000a26828841890d3f3a2a1d4083839c7a882fe050100\""
)

// Test user credentials
const (
	username1 = "username1"
	password1 = "87GridNEG3gKZ3I!"
	username2 = "username2"
	password2 = "RkB143NUCmok2f4!"
)

// Test public key hashes
const (
	pkh1 = integrationtest.AlicePKH
	pkh2 = integrationtest.BobPKH
	pkh3 = integrationtest.OpstestPKH
	pkh4 = integrationtest.Opstest1PKH
)

// HTTP status codes
const (
	statusOK           = 200
	statusCreated      = 201
	statusUnauthorized = 401
	statusForbidden    = 403
)

// JWT token structure types
type jwtHeader struct {
	Type      string `json:"typ"`
	Algorithm string `json:"alg"`
}

type jwtPayload struct {
	Expires uint64 `json:"exp"`
	User    string `json:"user"`
}

// Test helper functions

// setupJWTConfig creates a JWT configuration with the specified users
func setupJWTConfig(users map[string]*integrationtest.JwtUserData) integrationtest.Config {
	var config integrationtest.Config
	config.Read()
	config.Server.Jwt = integrationtest.JwtConfig{Users: users}
	return config
}

// setupAndRestart configures JWT and restarts the signatory service
func setupAndRestart(users map[string]*integrationtest.JwtUserData) {
	config := setupJWTConfig(users)
	integrationtest.Update_config(config)
	integrationtest.Restart_signatory()
}

// cleanup restores the original configuration
func cleanup() {
	integrationtest.Restore_config()
}

// makeRequest performs an HTTP POST request and returns status code and response body
func makeRequest(url string, body string, headers [][]string) (int, []byte, error) {
	reqBody := strings.NewReader(body)
	client := &http.Client{}

	req, err := http.NewRequest(http.MethodPost, url, reqBody)
	if err != nil {
		return 0, nil, fmt.Errorf("failed to create request: %w", err)
	}

	for _, header := range headers {
		req.Header.Add(header[0], header[1])
	}

	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	bytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, nil, fmt.Errorf("failed to read response body: %w", err)
	}

	return resp.StatusCode, bytes, nil
}

// request is a wrapper that panics on error for test convenience
func request(url string, body string, headers [][]string) (int, []byte) {
	code, bytes, err := makeRequest(url, body, headers)
	if err != nil {
		panic(err)
	}
	return code, bytes
}

// createHeaders creates a header slice for HTTP requests
func createHeaders(headers map[string]string) [][]string {
	var result [][]string
	for key, value := range headers {
		result = append(result, []string{key, value})
	}
	return result
}

// loginUser authenticates a user and returns the JWT token
func loginUser(t *testing.T, username, password string) string {
	headers := createHeaders(map[string]string{
		"Content-Type": "application/json",
		"username":     username,
		"password":     password,
	})

	code, bytes := request(loginURL, "", headers)
	require.Equal(t, statusCreated, code, "Login should succeed")

	token := string(bytes)
	require.Greater(t, len(token), 1, "Token should not be empty")
	require.NotContains(t, token, "signature", "Token should not contain signature")
	require.Equal(t, 2, strings.Count(token, "."), "JWT should have 3 parts separated by 2 dots")

	return token
}

// requestSignature requests a signature with the given token
func requestSignature(t *testing.T, endpoint, message, username, token string) (int, []byte) {
	headers := createHeaders(map[string]string{
		"Content-Type":  "application/json",
		"username":      username,
		"Authorization": "Bearer " + token,
	})

	return request(endpoint, message, headers)
}

// createUnsignedToken creates a JWT token with "none" algorithm for testing attacks
func createUnsignedToken(username string) string {
	header := jwtHeader{Type: "JWT", Algorithm: "none"}
	payload := jwtPayload{Expires: 9999999999, User: username}

	headerBytes, _ := json.Marshal(header)
	payloadBytes, _ := json.Marshal(payload)

	headerEncoded := base64.RawURLEncoding.EncodeToString(headerBytes)
	payloadEncoded := base64.RawURLEncoding.EncodeToString(payloadBytes)

	return headerEncoded + "." + payloadEncoded + ".8x-WJhWP7IXiyeFYTaxNg6IlJrXB9_2xvgUS3O_3aeE"
}

// Test functions

func TestJWTHappyPath(t *testing.T) {
	// Test without JWT configured - should succeed
	endpoint := baseURL + "keys/" + pkh1
	code, bytes := request(endpoint, message, nil)
	require.Equal(t, statusOK, code)
	require.Contains(t, string(bytes), "signature")

	// Configure JWT and test without token - should fail
	users := map[string]*integrationtest.JwtUserData{
		username1: {Password: password1, Secret: secret, Exp: 60},
	}

	setupAndRestart(users)
	defer cleanup()

	code, bytes = request(endpoint, message, nil)
	require.Equal(t, statusUnauthorized, code)
	assert.Equal(t, "token required", string(bytes))

	// Get JWT token and test with token - should succeed
	token := loginUser(t, username1, password1)

	code, bytes = requestSignature(t, endpoint, message, username1, token)
	require.Equal(t, statusOK, code)
	require.Contains(t, string(bytes), "signature")
}

func TestJWTCredentialFailure(t *testing.T) {
	users := map[string]*integrationtest.JwtUserData{
		username1: {Password: password1, Secret: secret, Exp: 60},
	}

	setupAndRestart(users)
	defer cleanup()

	// Test with wrong username
	headers := createHeaders(map[string]string{
		"Content-Type": "application/json",
		"username":     "username3",
		"password":     password1,
	})
	code, bytes := request(loginURL, "", headers)
	require.Equal(t, statusUnauthorized, code)
	assert.Equal(t, "Access denied", string(bytes))

	// Test with wrong password
	headers = createHeaders(map[string]string{
		"Content-Type": "application/json",
		"username":     username2,
		"password":     password1,
	})
	code, bytes = request(loginURL, "", headers)
	require.Equal(t, statusUnauthorized, code)
	assert.Equal(t, "Access denied", string(bytes))
}

func TestJWTExpiry(t *testing.T) {
	// Configure JWT with 1 minute expiry
	users := map[string]*integrationtest.JwtUserData{
		username1: {Password: password1, Secret: secret, Exp: 1},
	}

	setupAndRestart(users)
	defer cleanup()

	// Get token
	token := loginUser(t, username1, password1)

	// Wait for token to expire
	time.Sleep(time.Minute + time.Second)

	// Test with expired token
	endpoint := baseURL + "keys/" + pkh1
	code, bytes := requestSignature(t, endpoint, message, username1, token)
	require.Equal(t, statusUnauthorized, code)
	require.Equal(t, "Token is expired", string(bytes))
}

func TestAlgNoneAttack(t *testing.T) {
	users := map[string]*integrationtest.JwtUserData{
		username1: {Password: password1, Secret: secret, Exp: 60},
	}

	setupAndRestart(users)
	defer cleanup()

	// Create token with "none" algorithm
	token := createUnsignedToken(username1)

	endpoint := baseURL + "keys/" + pkh1
	code, bytes := requestSignature(t, endpoint, message, username1, token)
	require.Equal(t, statusUnauthorized, code)
	require.Equal(t, "'none' signature type is not allowed", string(bytes))
}

func TestSignatureIsVerified(t *testing.T) {
	users := map[string]*integrationtest.JwtUserData{
		username1: {Password: password1, Secret: secret, Exp: 60},
		username2: {Password: password2, Secret: secret, Exp: 60},
	}

	setupAndRestart(users)
	defer cleanup()

	// Get token for user1
	token := loginUser(t, username1, password1)
	parts := strings.Split(token, ".")

	// Create modified token with different payload but same signature
	payload := jwtPayload{Expires: 9999999999, User: username2}
	payloadBytes, _ := json.Marshal(payload)
	payloadEncoded := base64.RawURLEncoding.EncodeToString(payloadBytes)

	modifiedToken := parts[0] + "." + payloadEncoded + "." + parts[2]

	// Test with invalid signature
	endpoint := baseURL + "keys/" + pkh1
	code, bytes := requestSignature(t, endpoint, message, username2, modifiedToken)
	assert.Equal(t, statusUnauthorized, code)
	require.Contains(t, string(bytes), "signature is invalid")
}

func TestBadInputs(t *testing.T) {
	users := map[string]*integrationtest.JwtUserData{
		username1: {Password: password1, Secret: secret, Exp: 60},
	}

	setupAndRestart(users)
	defer cleanup()

	endpoint := baseURL + "keys/" + pkh1

	// Test without token
	code, bytes := request(endpoint, message, nil)
	assert.Equal(t, statusUnauthorized, code)
	assert.Equal(t, "token required", string(bytes))

	// Get valid token
	token := loginUser(t, username1, password1)

	// Test with malformed Authorization header (no space after Bearer)
	headers := createHeaders(map[string]string{
		"Content-Type":  "application/json",
		"username":      username1,
		"Authorization": "Bearer" + token,
	})
	code, bytes = request(endpoint, message, headers)
	assert.Equal(t, statusUnauthorized, code)
	assert.Contains(t, string(bytes), "looking for beginning of value")

	// Test without username header
	headers = createHeaders(map[string]string{
		"Content-Type":  "application/json",
		"Authorization": "Bearer " + token,
	})
	code, bytes = request(endpoint, message, headers)
	assert.Equal(t, statusUnauthorized, code)
	assert.Contains(t, string(bytes), "user not found")

	// Test without Authorization header
	headers = createHeaders(map[string]string{
		"Content-Type": "application/json",
		"username":     username1,
	})
	code, bytes = request(endpoint, message, headers)
	assert.Equal(t, statusUnauthorized, code)
	assert.Contains(t, string(bytes), "token required")

	// Test with empty headers
	headers = createHeaders(map[string]string{
		"Content-Type":  "",
		"username":      "",
		"Authorization": "",
	})
	code, bytes = request(endpoint, message, headers)
	assert.Equal(t, statusUnauthorized, code)
	assert.Contains(t, string(bytes), "token required")

	// Test login without username
	headers = createHeaders(map[string]string{
		"Content-Type": "application/json",
		"password":     password1,
	})
	code, bytes = request(loginURL, "", headers)
	assert.Equal(t, statusUnauthorized, code)
	assert.Contains(t, string(bytes), "username and password required")

	// Test login without password
	headers = createHeaders(map[string]string{
		"Content-Type": "application/json",
		"username":     username1,
	})
	code, bytes = request(loginURL, "", headers)
	assert.Equal(t, statusUnauthorized, code)
	assert.Contains(t, string(bytes), "username and password required")
}

func TestPasswordRotation(t *testing.T) {
	// Configure password rotation with expiry
	expiry, _, _ := strings.Cut(time.Now().Add(time.Minute).UTC().String(), ".")
	users := map[string]*integrationtest.JwtUserData{
		username1: {
			Password: password1,
			Secret:   secret,
			Exp:      60,
			CredExp:  expiry,
			NewCred: &integrationtest.JwtNewCred{
				Password: password2,
				Secret:   secret2,
				Exp:      60,
			},
		},
	}

	setupAndRestart(users)
	defer cleanup()

	// Test old password still works
	loginUser(t, username1, password1)

	// Test new password also works
	loginUser(t, username1, password2)

	// Wait for old password to expire
	time.Sleep(time.Minute + time.Second)

	// Test old password no longer works
	headers := createHeaders(map[string]string{
		"Content-Type": "application/json",
		"username":     username1,
		"password":     password1,
	})
	code, bytes := request(loginURL, "", headers)
	assert.Equal(t, statusUnauthorized, code)
	assert.Contains(t, string(bytes), "Access denied")

	// Test new password still works
	loginUser(t, username1, password2)
}

func TestPerPkh(t *testing.T) {
	// Configure users and PKH permissions
	users := map[string]*integrationtest.JwtUserData{
		username1: {Password: password1, Secret: secret},
		username2: {Password: password2, Secret: secret},
	}

	config := setupJWTConfig(users)

	// Configure PKH-specific permissions
	config.Tezos[pkh1].JwtUsers = []string{username1}
	config.Tezos[pkh2].JwtUsers = []string{username2}
	config.Tezos[pkh3].JwtUsers = []string{username1, username2}
	config.Tezos[pkh3].Allow = map[string][]string{"generic": {"transaction"}}
	config.Tezos[pkh4].Allow = map[string][]string{"generic": {"transaction"}}

	integrationtest.Update_config(config)
	defer cleanup()
	integrationtest.Restart_signatory()

	// Login both users
	token1 := loginUser(t, username1, password1)
	token2 := loginUser(t, username2, password2)

	// Test PKH1 - only user1 can access
	endpoint1 := baseURL + "keys/" + pkh1

	// User1 should succeed
	code, bytes := requestSignature(t, endpoint1, message, username1, token1)
	assert.Equal(t, statusOK, code)
	assert.Contains(t, string(bytes), "signature")

	// User2 should be forbidden
	code, bytes = requestSignature(t, endpoint1, message, username2, token2)
	assert.Equal(t, statusForbidden, code)
	assert.Contains(t, string(bytes), "user `username2' is not authorized to access "+pkh1)

	// User2 trying to impersonate user1 should fail
	code, bytes = requestSignature(t, endpoint1, message, username1, token2)
	assert.Equal(t, statusUnauthorized, code)
	assert.Contains(t, string(bytes), "JWT: invalid token")

	// Test PKH2 - only user2 can access
	endpoint2 := baseURL + "keys/" + pkh2

	// User2 should succeed
	code, bytes = requestSignature(t, endpoint2, message, username2, token2)
	assert.Equal(t, statusOK, code)
	assert.Contains(t, string(bytes), "signature")

	// User1 should be forbidden
	code, bytes = requestSignature(t, endpoint2, message, username1, token1)
	assert.Equal(t, statusForbidden, code)
	assert.Contains(t, string(bytes), "user `username1' is not authorized to access "+pkh2)

	// Test PKH3 - both users can access
	endpoint3 := baseURL + "keys/" + pkh3

	// Both users should succeed
	code, bytes = requestSignature(t, endpoint3, message, username1, token1)
	assert.Equal(t, statusOK, code)
	assert.Contains(t, string(bytes), "signature")

	code, bytes = requestSignature(t, endpoint3, message, username2, token2)
	assert.Equal(t, statusOK, code)
	assert.Contains(t, string(bytes), "signature")

	// Test PKH4 - no JWT users configured, so both should work
	endpoint4 := baseURL + "keys/" + pkh4

	// Both users should succeed
	code, bytes = requestSignature(t, endpoint4, message, username1, token1)
	assert.Equal(t, statusOK, code)
	assert.Contains(t, string(bytes), "signature")

	code, bytes = requestSignature(t, endpoint4, message, username2, token2)
	assert.Equal(t, statusOK, code)
	assert.Contains(t, string(bytes), "signature")
}
