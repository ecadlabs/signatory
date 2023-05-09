package integrationtest

import (
	"io"
	"log"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	endpoint = "http://localhost:6732/keys/tz1VSUr8wwNhLAzempoch5d6hLRiTh8Cjcjb"
	login    = "http://localhost:6732/login"
	message  = "\"03c8e312c61a5fd8e9d6ff1d5dccf900e10b5769e55738eb365e99636e3c3fd1d76c006b82198cb179e8306c1bedd08f12dc863f328886df0202e90700c0843d0000a26828841890d3f3a2a1d4083839c7a882fe050100\""
)

func TestJWTHappyPath(t *testing.T) {
	//sanity check: request a signature without JWT configured and see it succeed
	code, bytes := request(endpoint, message, nil)
	require.Equal(t, 200, code)
	require.Contains(t, string(bytes), "signature")

	//configure JWT and make the same request, and see it fail
	var c Config
	c.Read("signatory.yaml")
	c.Server.Jwt = JwtConfig{Users: map[string]*JwtUserData{"username1": {Password: "password1", Secret: "secret1", Exp: 60}}}
	backup_then_update_config(c)
	defer restore_config()
	restart_signatory()
	code, bytes = request(endpoint, message, nil)
	require.Equal(t, 401, code)
	assert.Equal(t, "token required", string(bytes))

	//provide credentials in the header of the same request to fetch a bearer token
	var h = [][]string{{"Content-Type", "application/json"}, {"username", "username1"}, {"password", "password1"}}
	code, bytes = request(login, "", h)
	require.Equal(t, 201, code)
	token := string(bytes)
	require.Greater(t, len(token), 1)
	require.NotContains(t, token, "signature")
	require.Equal(t, 2, strings.Count(token, "."))

	//request a signature with a token
	h = [][]string{{"Content-Type", "application/json"}, {"username", "username1"}, {"Authorization", "Bearer " + token}}
	code, bytes = request(endpoint, message, h)
	require.Equal(t, 200, code)
	require.Contains(t, string(bytes), "signature")
}

func request(url string, body string, headers [][]string) (int, []byte) {
	reqbody := strings.NewReader(body)
	client := &http.Client{}
	req, err := http.NewRequest(http.MethodPost, url, reqbody)
	if err != nil {
		log.Fatal(err)
	}
	for _, h := range headers {
		req.Header.Add(h[0], h[1])
	}
	resp, err := client.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()
	bytes, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}
	//fmt.Println(string(bytes))
	return resp.StatusCode, bytes
}
