package integrationtest

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	baseUrl   = "http://localhost:6732/"
	secret    = "!sEtcU5RwLQYsA5qQ1c6zpo3FljQxfAKP"
	endpoint  = baseUrl + "keys/tz1VSUr8wwNhLAzempoch5d6hLRiTh8Cjcjb"
	login     = baseUrl + "login"
	message   = "\"03c8e312c61a5fd8e9d6ff1d5dccf900e10b5769e55738eb365e99636e3c3fd1d76c006b82198cb179e8306c1bedd08f12dc863f328886df0202e90700c0843d0000a26828841890d3f3a2a1d4083839c7a882fe050100\""
	username1 = "username1"
	password1 = "87GridNEG3gKZ3I!"
	username2 = "username2"
	password2 = "RkB143NUCmok2f4!"
)

func TestJWTHappyPath(t *testing.T) {
	//sanity check: request a signature without JWT configured and see it succeed
	code, bytes := request(endpoint, message, nil)
	require.Equal(t, 200, code)
	require.Contains(t, string(bytes), "signature")

	//configure JWT and make the same request, and see it fail because you have no token
	var c Config
	c.Read()
	c.Server.Jwt = JwtConfig{Users: map[string]*JwtUserData{username1: {Password: password1, Secret: secret, Exp: 60}}}
	backup_then_update_config(c)
	defer restore_config()
	restart_signatory()
	code, bytes = request(endpoint, message, nil)
	require.Equal(t, 401, code)
	assert.Equal(t, "token required", string(bytes))

	//get a bearer token from the login endpoint
	var h = [][]string{{"Content-Type", "application/json"}, {"username", username1}, {"password", password1}}
	code, bytes = request(login, "", h)
	require.Equal(t, 201, code)
	token := string(bytes)
	require.Greater(t, len(token), 1)
	require.NotContains(t, token, "signature")
	require.Equal(t, 2, strings.Count(token, "."))

	//request with a token is successful
	h = [][]string{{"Content-Type", "application/json"}, {"username", username1}, {"Authorization", "Bearer " + token}}
	code, bytes = request(endpoint, message, h)
	require.Equal(t, 200, code)
	require.Contains(t, string(bytes), "signature")
}

func TestJWTCredentialFailure(t *testing.T) {
	var c Config
	c.Read()
	c.Server.Jwt = JwtConfig{Users: map[string]*JwtUserData{username1: {Password: password1, Secret: secret, Exp: 60}}}
	backup_then_update_config(c)
	defer restore_config()
	restart_signatory()

	//wrong username
	var h = [][]string{{"Content-Type", "application/json"}, {"username", "username3"}, {"password", password1}}
	code, bytes := request(login, "", h)
	require.Equal(t, 401, code)
	assert.Equal(t, "Access denied", string(bytes))

	//wrong password
	h = [][]string{{"Content-Type", "application/json"}, {"username", username2}, {"password", password1}}
	code, _ = request(login, "", h)
	require.Equal(t, 401, code)
	require.Equal(t, "Access denied", string(bytes))
}

func TestJWTExpiry(t *testing.T) {
	var c Config
	c.Read()
	//configure a 1 minute expiry
	c.Server.Jwt = JwtConfig{Users: map[string]*JwtUserData{username1: {Password: password1, Secret: secret, Exp: 1}}}
	backup_then_update_config(c)
	defer restore_config()
	restart_signatory()

	//get a token
	var h = [][]string{{"Content-Type", "application/json"}, {"username", username1}, {"password", password1}}
	code, bytes := request(login, "", h)
	require.Equal(t, 201, code)
	token := string(bytes)

	//allow token to expire
	time.Sleep(time.Second * 61)

	//request a signature with an expired token
	h = [][]string{{"Content-Type", "application/json"}, {"username", username1}, {"Authorization", "Bearer " + token}}
	code, bytes = request(endpoint, message, h)
	require.Equal(t, 401, code)
	require.Equal(t, string(bytes), "Token is expired")
}

func request(url string, body string, headers [][]string) (int, []byte) {
	reqbody := strings.NewReader(body)
	client := &http.Client{}
	req, err := http.NewRequest(http.MethodPost, url, reqbody)
	if err != nil {
		panic(err)
	}
	for _, h := range headers {
		req.Header.Add(h[0], h[1])
	}
	resp, err := client.Do(req)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	bytes, err := io.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}
	return resp.StatusCode, bytes
}

func TestAlgNoneAttack(t *testing.T) {
	var c Config
	c.Read()
	c.Server.Jwt = JwtConfig{Users: map[string]*JwtUserData{username1: {Password: password1, Secret: secret, Exp: 60}}}
	backup_then_update_config(c)
	defer restore_config()
	restart_signatory()

	user := "username1"
	token := createUnsignedToken(user)
	var h = [][]string{{"Content-Type", "application/json"}, {"username", username1}, {"Authorization", "Bearer " + token}}
	code, bytes := request(endpoint, message, h)
	require.Equal(t, 401, code)
	require.Equal(t, "'none' signature type is not allowed", string(bytes))
}

func createUnsignedToken(username string) string {
	h := jwtHeader{Type: "JWT", Algorithm: "none"}
	p := jwtPayload{Expires: 9999999999, User: username}

	hb, _ := json.Marshal(h)
	pb, _ := json.Marshal(p)

	he := base64.RawURLEncoding.EncodeToString(hb)
	pe := base64.RawURLEncoding.EncodeToString(pb)

	return he + "." + pe + ".8x-WJhWP7IXiyeFYTaxNg6IlJrXB9_2xvgUS3O_3aeE"
}

type jwtHeader struct {
	Type      string `json:"typ"`
	Algorithm string `json:"alg"`
}

type jwtPayload struct {
	Expires uint64 `json:"exp"`
	User    string `json:"user"`
}

func TestSignatureIsVerified(t *testing.T) {
	var c Config
	c.Read()
	c.Server.Jwt = JwtConfig{Users: map[string]*JwtUserData{username1: {Password: password1, Secret: secret, Exp: 60},
		username2: {Password: password2, Secret: secret, Exp: 60}}}
	backup_then_update_config(c)
	defer restore_config()
	restart_signatory()

	//get a token
	var h = [][]string{{"Content-Type", "application/json"}, {"username", username1}, {"password", password1}}
	code, bytes := request(login, "", h)
	require.Equal(t, 201, code)
	token := string(bytes)
	parts := strings.Split(token, ".")

	//write a slightly different payload, but, keep the same header and signature
	p := jwtPayload{Expires: 9999999999, User: username2}
	pb, _ := json.Marshal(p)
	pe := base64.RawURLEncoding.EncodeToString(pb)

	newtoken := parts[0] + "." + pe + "." + parts[2]

	//request a signature with a token whose signature is not valid
	h = [][]string{{"Content-Type", "application/json"}, {"username", username2}, {"Authorization", "Bearer " + newtoken}}
	code, bytes = request(endpoint, message, h)
	assert.Equal(t, 401, code)
	require.Contains(t, string(bytes), "signature is invalid")
}

func TestBadInputs(t *testing.T) {
	//configure JWT and make the same request, and see it fail
	var c Config
	c.Read()
	c.Server.Jwt = JwtConfig{Users: map[string]*JwtUserData{username1: {Password: password1, Secret: secret, Exp: 60}}}
	backup_then_update_config(c)
	defer restore_config()
	restart_signatory()
	code, bytes := request(endpoint, message, nil)
	assert.Equal(t, 401, code)
	assert.Equal(t, "token required", string(bytes))

	//provide credentials in the header of the same request to fetch a bearer token
	var h = [][]string{{"Content-Type", "application/json"}, {"username", "username1"}, {"password", "password1"}}
	code, bytes = request(login, "", h)
	assert.Equal(t, 201, code)
	token := string(bytes)
	assert.Greater(t, len(token), 1)
	assert.NotContains(t, token, "signature")
	assert.Equal(t, 2, strings.Count(token, "."))

	//there is no whitespace after "Bearer" in the Authorization header, on purpose
	h = [][]string{{"Content-Type", "application/json"}, {"username", username1}, {"Authorization", "Bearer" + token}}
	code, bytes = request(endpoint, message, h)
	assert.Equal(t, 401, code)
	assert.Contains(t, string(bytes), "looking for beginning of value")

	//missing username header
	h = [][]string{{"Content-Type", "application/json"}, {"Authorization", "Bearer " + token}}
	code, bytes = request(endpoint, message, h)
	assert.Equal(t, 401, code)
	assert.Contains(t, string(bytes), "user not found")

	//missing token header
	h = [][]string{{"Content-Type", "application/json"}, {"username", username1}}
	code, bytes = request(endpoint, message, h)
	assert.Equal(t, 401, code)
	assert.Contains(t, string(bytes), "token required")

	//empty string headers
	h = [][]string{{"Content-Type", ""}, {"username", ""}, {"Authorization", ""}}
	code, bytes = request(endpoint, message, h)
	assert.Equal(t, 401, code)
	assert.Contains(t, string(bytes), "token required")

	//login no username
	h = [][]string{{"Content-Type", "application/json"}, {"password", password1}}
	code, bytes = request(login, "", h)
	assert.Equal(t, 401, code)
	assert.Contains(t, string(bytes), "username and password required")

	//login no password
	h = [][]string{{"Content-Type", "application/json"}, {"username", username1}}
	code, bytes = request(login, "", h)
	assert.Equal(t, 401, code)
	assert.Contains(t, string(bytes), "username and password required")
}

func TestPasswordRotation(t *testing.T) {
	var c Config
	c.Read()
	c.Server.Jwt = JwtConfig{Users: map[string]*JwtUserData{username1: {Password: password1, Secret: secret, Exp: 60, CredExp: 1, NewCred: &JwtNewCred{Password: "password2", Secret: secret, Exp: 60}}}}
	backup_then_update_config(c)
	defer restore_config()
	restart_signatory()

	//use old password
	var h = [][]string{{"Content-Type", "application/json"}, {"username", username1}, {"password", password1}}
	code, bytes := request(login, "", h)
	require.Equal(t, 201, code)
	token := string(bytes)
	assert.NotContains(t, token, "signature")
	assert.Equal(t, 2, strings.Count(token, "."))

	//use new password
	h = [][]string{{"Content-Type", "application/json"}, {"username", username1}, {"password", password2}}
	code, bytes = request(login, "", h)
	assert.Equal(t, 201, code)
	token = string(bytes)
	assert.NotContains(t, token, "signature")
	assert.Equal(t, 2, strings.Count(token, "."))

	//wait for old password to expire
	time.Sleep(time.Minute + time.Second)

	//old password doesn't work now
	h = [][]string{{"Content-Type", "application/json"}, {"username", username1}, {"password", password1}}
	code, bytes = request(login, "", h)
	assert.Equal(t, 401, code)
	assert.Contains(t, string(bytes), "Access denied")

	//new password still works
	h = [][]string{{"Content-Type", "application/json"}, {"username", username1}, {"password", password2}}
	code, bytes = request(login, "", h)
	assert.Equal(t, 201, code)
	token = string(bytes)
	assert.NotContains(t, token, "signature")
	assert.Equal(t, 2, strings.Count(token, "."))
}

func TestPerPkh(t *testing.T) {
	var pkh1 = "tz1VSUr8wwNhLAzempoch5d6hLRiTh8Cjcjb"
	var pkh2 = "tz1aSkwEot3L2kmUvcoxzjMomb9mvBNuzFK6"
	var pkh3 = "tz1RKGhRF4TZNCXEfwyqZshGsVfrZeVU446B"
	var pkh4 = "tz1R8HJMzVdZ9RqLCknxeq9w5rSbiqJ41szi"
	var base = baseUrl + "keys/"
	var url1 = base + pkh1
	var url2 = base + pkh2
	var url3 = base + pkh3
	var url4 = base + pkh4

	var c Config
	c.Read()
	c.Server.Jwt = JwtConfig{Users: map[string]*JwtUserData{username1: {Password: password1, Secret: secret},
		username2: {Password: password2, Secret: secret}}}

	c.Tezos[pkh1].JwtUsers = []string{username1}
	c.Tezos[pkh2].JwtUsers = []string{username2}
	c.Tezos[pkh3].JwtUsers = []string{username1, username2}
	c.Tezos[pkh3].Allow = map[string][]string{"generic": {"transaction"}}
	c.Tezos[pkh4].Allow = map[string][]string{"generic": {"transaction"}}

	backup_then_update_config(c)
	defer restore_config()
	restart_signatory()

	//user1 login
	var h = [][]string{{"Content-Type", "application/json"}, {"username", username1}, {"password", password1}}
	code, bytes := request(login, "", h)
	require.Equal(t, 201, code)
	token1 := string(bytes)

	//user2 login
	h = [][]string{{"Content-Type", "application/json"}, {"username", username2}, {"password", password2}}
	code, bytes = request(login, "", h)
	require.Equal(t, 201, code)
	token2 := string(bytes)

	//pkh1 signs for user1
	h = [][]string{{"Content-Type", "application/json"}, {"username", username1}, {"Authorization", "Bearer " + token1}}
	code, bytes = request(url1, message, h)
	assert.Equal(t, 200, code)
	assert.Contains(t, string(bytes), "signature")

	//pkh1 does not sign for user2
	h = [][]string{{"Content-Type", "application/json"}, {"username", username2}, {"Authorization", "Bearer " + token2}}
	code, bytes = request(url1, message, h)
	assert.Equal(t, 403, code)
	assert.Contains(t, string(bytes), "user `username2' is not authorized to access "+pkh1)

	//ISSUE #372 pkh1 does not sign for malicious user2 who tries to be user1
	h = [][]string{{"Content-Type", "application/json"}, {"username", username1}, {"Authorization", "Bearer " + token2}}
	code, bytes = request(url1, message, h)
	assert.Equal(t, 403, code)
	assert.Contains(t, string(bytes), "user `username2' is not authorized to access "+pkh1)

	//pkh2 signs for user2
	h = [][]string{{"Content-Type", "application/json"}, {"username", username2}, {"Authorization", "Bearer " + token2}}
	code, bytes = request(url2, message, h)
	assert.Equal(t, 200, code)
	assert.Contains(t, string(bytes), "signature")

	//pkh2 does not sign for user1
	h = [][]string{{"Content-Type", "application/json"}, {"username", username1}, {"Authorization", "Bearer " + token1}}
	code, bytes = request(url2, message, h)
	assert.Equal(t, 403, code)
	assert.Contains(t, string(bytes), "user `username1' is not authorized to access "+pkh2)

	//pkh3 signs for both user1 and user2 because both are configured
	h = [][]string{{"Content-Type", "application/json"}, {"username", username1}, {"Authorization", "Bearer " + token1}}
	code, bytes = request(url3, message, h)
	assert.Equal(t, 200, code)
	assert.Contains(t, string(bytes), "signature")
	h = [][]string{{"Content-Type", "application/json"}, {"username", username2}, {"Authorization", "Bearer " + token2}}
	code, bytes = request(url3, message, h)
	assert.Equal(t, 200, code)
	assert.Contains(t, string(bytes), "signature")

	//pkh4 signs for both user1 and user2 because nobody is configured
	h = [][]string{{"Content-Type", "application/json"}, {"username", username1}, {"Authorization", "Bearer " + token1}}
	code, bytes = request(url4, message, h)
	assert.Equal(t, 200, code)
	assert.Contains(t, string(bytes), "signature")
	h = [][]string{{"Content-Type", "application/json"}, {"username", "username2"}, {"Authorization", "Bearer " + token2}}
	code, bytes = request(url4, message, h)
	assert.Equal(t, 200, code)
	assert.Contains(t, string(bytes), "signature")
}
