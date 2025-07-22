package server_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	tz "github.com/ecadlabs/gotez/v2"
	"github.com/ecadlabs/gotez/v2/crypt"
	"github.com/ecadlabs/signatory/pkg/server"
	"github.com/ecadlabs/signatory/pkg/signatory"
	"github.com/ecadlabs/signatory/pkg/vault"
	"github.com/stretchr/testify/require"
)

type signerMock struct {
	SignResponse      crypt.Signature
	SignedData        []byte
	SignError         error
	PublicKeyResponse *signatory.PublicKey
	PublicKeyError    error
}

func (c *signerMock) Sign(ctx context.Context, req *signatory.SignRequest) (crypt.Signature, error) {
	return c.SignResponse, c.SignError
}

func (c *signerMock) ProvePossession(ctx context.Context, req *signatory.SignRequest) (crypt.Signature, error) {
	return c.SignResponse, c.SignError
}

func (c *signerMock) SignSequencerBlueprint(ctx context.Context, req *signatory.SignRequest) (crypt.Signature, []byte, error) {
	return c.SignResponse, c.SignedData, c.SignError

}

func (c *signerMock) SignSequencerSignal(ctx context.Context, req *signatory.SignRequest) (crypt.Signature, []byte, error) {
	return c.SignResponse, c.SignedData, c.SignError
}

func (c *signerMock) GetPublicKey(ctx context.Context, keyHash crypt.PublicKeyHash) (*signatory.PublicKey, error) {
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

type mockRef struct {
	key crypt.PublicKey
}

func (k *mockRef) PublicKey() crypt.PublicKey { return k.key }
func (k *mockRef) String() string             { return k.key.Hash().String() }
func (k *mockRef) Vault() vault.Vault         { panic("not implemented") }
func (k *mockRef) Sign(ctx context.Context, message []byte) (crypt.Signature, error) {
	panic("not implemented")
}

func TestGetPublicKey(t *testing.T) {
	type testCase struct {
		Name       string
		StatusCode int
		Response   *signatory.PublicKey
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
			Response:   &signatory.PublicKey{KeyReference: &mockRef{mustPk(&tz.Ed25519PublicKey{1, 2, 3})}},
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

func TestProvePossession(t *testing.T) {
	type testCase struct {
		Name       string
		StatusCode int
		Response   tz.Signature
		Error      error
		Expected   string
	}

	cases := []testCase{
		{
			Name:       "Ok",
			StatusCode: http.StatusOK,
			Response:   &tz.BLSSignature{0xa0, 0xd9, 0x95, 0xe9, 0xa6, 0x35, 0xfd, 0x10, 0xee, 0x28, 0xa4, 0x94, 0xa8, 0x0a, 0x8c, 0xb0, 0x1a, 0x2b, 0x25, 0x5e, 0xc1, 0x95, 0x27, 0xed, 0x35, 0xdd, 0x17, 0x18, 0xee, 0x6a, 0xdc, 0x22, 0x3c, 0x77, 0x0f, 0x8b, 0xf7, 0xda, 0x88, 0x80, 0xc3, 0x95, 0xef, 0xa7, 0xd3, 0x93, 0xc0, 0x95, 0x04, 0xe9, 0x58, 0x8f, 0xa2, 0x64, 0xdf, 0x6d, 0x39, 0x96, 0xb2, 0x4c, 0x84, 0xe0, 0x8f, 0x95, 0x8a, 0xbe, 0xf5, 0x70, 0xab, 0x8b, 0x50, 0xfb, 0x29, 0x30, 0xb4, 0xbf, 0x20, 0x4b, 0x48, 0xc3, 0x11, 0xb9, 0x0c, 0xa1, 0xd6, 0xba, 0x3b, 0x5d, 0xe1, 0x45, 0x0a, 0x6e, 0x5b, 0x88, 0xd1, 0xc9},
			Expected:   "{\"bls_prove_possession\":\"BLsigAnMm6w9C3xzsGZiUAxNPX5SkpWqhKDbXttbbWbWTFPyu2cMTKZkCiwWMj1dP55yQuoKvhwE6mESqLBAwSDoBnbzSoGZhTJgc8ZFJbYQhwnBusHUVXXmHv6NWAhoZa1gfHXLqrEinH\"}\n",
		},
		{
			Name:       "Prove possession error",
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

			req, err := http.NewRequest("GET", s.URL+"/bls_prove_possession/"+tz.Ed25519PublicKeyHash{}.String(), nil)
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
