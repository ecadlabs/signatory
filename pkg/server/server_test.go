package server_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	tz "github.com/ecadlabs/gotez"
	"github.com/ecadlabs/signatory/pkg/crypt"
	"github.com/ecadlabs/signatory/pkg/server"
	"github.com/ecadlabs/signatory/pkg/tezos"
	"github.com/stretchr/testify/require"
)

type signerMock struct {
	SignResponse      crypt.Signature
	SignError         error
	PublicKeyResponse *tezos.PublicKey
	PublicKeyError    error
}

func (c *signerMock) Sign(ctx context.Context, req *tezos.SignRequest) (crypt.Signature, error) {
	return c.SignResponse, c.SignError
}

func (c *signerMock) GetPublicKey(ctx context.Context, keyHash crypt.PublicKeyHash) (*tezos.PublicKey, error) {
	if c.PublicKeyResponse == nil && c.PublicKeyError == nil {
		return nil, errors.New("key not found")
	}
	return c.PublicKeyResponse, c.PublicKeyError
}

func TestSign(t *testing.T) {
	type testCase struct {
		Name       string
		Request    string
		StatusCode int
		Response   tz.Signature
		Error      error
		Expected   string
	}

	cases := []testCase{
		{
			Name:       "Bad request",
			StatusCode: http.StatusBadRequest,
			Expected:   "[{\"id\":\"failure\",\"kind\":\"temporary\",\"msg\":\"unexpected end of JSON input\"}]\n",
		},
		{
			Name:       "Invalid body",
			Request:    "\x03",
			StatusCode: http.StatusBadRequest,
			Expected:   "[{\"id\":\"failure\",\"kind\":\"temporary\",\"msg\":\"invalid character '\\\\x03' looking for beginning of value\"}]\n",
		},
		{
			Name:       "Invalid hex",
			Request:    "\"03ZZZZ\"",
			StatusCode: http.StatusBadRequest,
			Expected:   "[{\"id\":\"failure\",\"kind\":\"temporary\",\"msg\":\"encoding/hex: invalid byte: U+005A 'Z'\"}]\n",
		},
		{
			Name:       "Ok",
			Request:    "\"03123453\"",
			StatusCode: http.StatusOK,
			Response:   &tz.Ed25519Signature{1, 2, 3},
			Expected:   "{\"signature\":\"edsigtXwQk7vJvUGLVjSDqE3egYMVYVvDctZCXnXrbecmB85kfN51fib1NKq6aDiVHYDNGMid1EW7hfq92ZUXYsag8Gyx4GFyU6\"}\n",
		},
		{
			Name:       "Signature error",
			Request:    "\"03123453\"",
			StatusCode: http.StatusInternalServerError,
			Error:      errors.New("error"),
			Expected:   "[{\"id\":\"failure\",\"kind\":\"temporary\",\"msg\":\"error\"}]\n",
		},
	}

	for _, c := range cases {
		t.Run(c.Name, func(t *testing.T) {
			sig := &signerMock{
				SignError: c.Error,
			}

			if c.Response != nil {
				s, err := crypt.NewSignature(c.Response)
				if err != nil {
					t.Fatal(err)
				}
				sig.SignResponse = s
			}

			srv := &server.Server{
				Signer: sig,
			}

			handler, err := srv.Handler()
			if err != nil {
				t.Fatal(err)
			}

			s := httptest.NewServer(handler)
			defer s.Close()

			var body io.Reader
			if c.Request != "" {
				body = strings.NewReader(c.Request)
			}

			req, err := http.NewRequest("POST", s.URL+"/keys/"+tz.Ed25519PublicKeyHash{}.String(), body)
			if err != nil {
				t.Fatal(err)
			}
			resp, err := s.Client().Do(req)
			if err != nil {
				t.Fatal(err)
			}

			require.Equal(t, c.StatusCode, resp.StatusCode)

			b, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatal(err)
			}

			require.Equal(t, c.Expected, string(b))
		})
	}
}

func TestGetPublicKey(t *testing.T) {
	type testCase struct {
		Name       string
		StatusCode int
		Response   *tezos.PublicKey
		Error      error
		Expected   string
	}

	mustPk := func(pk tz.PublicKey) crypt.PublicKey {
		out, err := crypt.NewPublicKey(pk)
		if err != nil {
			panic(err)
		}
		return out
	}

	cases := []testCase{
		{
			Name:       "ReadError",
			StatusCode: http.StatusInternalServerError,
			Error:      errors.New("test"),
			Expected:   "[{\"id\":\"failure\",\"kind\":\"temporary\",\"msg\":\"test\"}]\n",
		},
		{
			Name:       "Normal",
			StatusCode: http.StatusOK,
			Response:   &tezos.PublicKey{PublicKey: mustPk(&tz.Ed25519PublicKey{1, 2, 3})},
			Expected:   "{\"public_key\":\"edpktefgU4dfKqN1rZVBwBP8ZueBoJZfhDS3kHPSbo8c3aGPrMrunt\"}\n",
		},
	}

	for _, c := range cases {
		t.Run(c.Name, func(t *testing.T) {
			sig := &signerMock{
				PublicKeyError:    c.Error,
				PublicKeyResponse: c.Response,
			}

			srv := &server.Server{
				Signer: sig,
			}

			handler, err := srv.Handler()
			if err != nil {
				t.Fatal(err)
			}

			s := httptest.NewServer(handler)
			defer s.Close()

			req, err := http.NewRequest("GET", s.URL+"/keys/"+tz.Ed25519PublicKeyHash{}.String(), nil)
			if err != nil {
				t.Fatal(err)
			}
			resp, err := s.Client().Do(req)
			if err != nil {
				t.Fatal(err)
			}

			require.Equal(t, c.StatusCode, resp.StatusCode)

			b, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatal(err)
			}

			require.Equal(t, c.Expected, string(b))
		})
	}
}
