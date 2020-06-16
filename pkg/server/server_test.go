package server

import (
	"bytes"
	"context"
	"errors"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ecadlabs/signatory/pkg/signatory"
	"github.com/stretchr/testify/require"
)

type fakeSignatory struct {
	SignResponse      string
	SignError         error
	PublicKeyResponse *signatory.PublicKey
	PublicKeyError    error
}

func (c *fakeSignatory) Sign(ctx context.Context, keyHash string, message []byte) (string, error) {
	return c.SignResponse, c.SignError
}

func (c *fakeSignatory) GetPublicKey(ctx context.Context, keyHash string) (*signatory.PublicKey, error) {
	return c.PublicKeyResponse, c.PublicKeyError
}

func toReadCloser(str string) io.ReadCloser {
	return ioutil.NopCloser(bytes.NewReader([]byte(str)))
}

func TestSign(t *testing.T) {
	type testCase struct {
		Name       string
		Request    []byte
		StatusCode int
		Response   string
		Error      error
		Expected   []byte
	}

	cases := []testCase{
		{
			Name:       "Bad request",
			StatusCode: http.StatusBadRequest,
			Expected:   []byte("{\"error\":\"unexpected end of JSON input\"}\n"),
		},
		{
			Name:       "Invalid body",
			Request:    []byte("03"),
			StatusCode: http.StatusBadRequest,
			Expected:   []byte("{\"error\":\"invalid character '3' after top-level value\"}\n"),
		},
		{
			Name:       "Invalid hex",
			Request:    []byte("\"03ZZZZ\""),
			StatusCode: http.StatusBadRequest,
			Expected:   []byte("{\"error\":\"encoding/hex: invalid byte: U+005A 'Z'\"}\n"),
		},
		{
			Name:       "Ok",
			Request:    []byte("\"03123453\""),
			StatusCode: http.StatusOK,
			Response:   "signature",
			Expected:   []byte("{\"signature\":\"signature\"}\n"),
		},
		{
			Name:       "Signature error",
			Request:    []byte("\"03123453\""),
			StatusCode: http.StatusInternalServerError,
			Error:      errors.New("error"),
			Expected:   []byte("{\"error\":\"error\"}\n"),
		},
	}

	for _, c := range cases {
		t.Run(c.Name, func(t *testing.T) {
			sig := &fakeSignatory{
				SignError:    c.Error,
				SignResponse: c.Response,
			}

			srv := &Server{
				Signer: sig,
			}

			var body io.Reader
			if c.Request != nil {
				body = bytes.NewReader(c.Request)
			}

			r := httptest.NewRequest("POST", "http://irrelevant.com", body)
			resp := httptest.NewRecorder()
			srv.signHandler(resp, r)

			require.Equal(t, resp.Code, c.StatusCode)

			b, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				t.Errorf(err.Error())
			}

			require.Equal(t, b, c.Expected)
		})
	}
}

func TestGetPublicKey(t *testing.T) {
	type testCase struct {
		Name       string
		StatusCode int
		Response   *signatory.PublicKey
		Error      error
		Expected   []byte
	}

	cases := []testCase{
		{
			Name:       "Read Error",
			StatusCode: http.StatusInternalServerError,
			Error:      errors.New("test"),
			Expected:   []byte("{\"error\":\"test\"}\n"),
		},
		{
			Name:       "Normal case",
			StatusCode: http.StatusOK,
			Response:   &signatory.PublicKey{PublicKey: "key"},
			Expected:   []byte("{\"public_key\":\"key\"}\n"),
		},
	}

	for _, c := range cases {
		t.Run(c.Name, func(t *testing.T) {
			sig := &fakeSignatory{
				PublicKeyError:    c.Error,
				PublicKeyResponse: c.Response,
			}

			srv := &Server{
				Signer: sig,
			}

			r := httptest.NewRequest("GET", "http://irrelevant.com", nil)
			resp := httptest.NewRecorder()
			srv.getKeyHandler(resp, r)

			require.Equal(t, resp.Code, c.StatusCode)

			b, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				t.Errorf(err.Error())
			}

			require.Equal(t, b, c.Expected)
		})
	}
}
