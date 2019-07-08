package server_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ecadlabs/signatory/server"
)

type FakeSignatory struct {
	Response string
	Error    error

	ReadResponse string
	ReadError    error
}

func (c *FakeSignatory) Sign(ctx context.Context, keyHash string, message []byte) (string, error) {
	return c.Response, c.Error
}
func (c *FakeSignatory) GetPublicKey(ctx context.Context, keyHash string) (string, error) {
	return c.ReadResponse, c.ReadError
}

func toReadCloser(str string) io.ReadCloser {
	return ioutil.NopCloser(bytes.NewReader([]byte(str)))
}

func TestSign(t *testing.T) {
	type Case struct {
		Name        string
		StatusCode  int
		Body        io.ReadCloser
		SigResponse string
		SigError    error
		Expected    string
	}

	sampleSig := "sig"

	errReading := "{\"error\":\"error reading the request\"}\n"
	errSig := "{\"error\":\"error signing the request\"}\n"
	expectedSig := fmt.Sprintf("{\"signature\":\"%s\"}\n", sampleSig)

	cases := []Case{
		Case{Name: "Bad request", StatusCode: http.StatusBadRequest, Expected: errReading},
		Case{Name: "Invalid body", StatusCode: http.StatusBadRequest, Expected: errReading, Body: toReadCloser("03")},
		Case{Name: "Invalid hex", StatusCode: http.StatusBadRequest, Expected: errReading, Body: toReadCloser("\"03ZZZZ\"")},
		Case{Name: "Ok", StatusCode: http.StatusOK, Expected: expectedSig, SigResponse: sampleSig, Body: toReadCloser("\"03123453\"")},
		Case{Name: "Signature error", StatusCode: http.StatusInternalServerError, Expected: errSig, SigError: errors.New("test"), Body: toReadCloser("\"03123453\"")},
	}

	for _, c := range cases {
		t.Run(c.Name, func(t *testing.T) {
			sig := &FakeSignatory{
				Error:    c.SigError,
				Response: c.SigResponse,
			}
			srv := server.NewServer(sig, nil)
			r := httptest.NewRequest("POST", "http://irrelevant.com", c.Body)
			rr := httptest.NewRecorder()
			srv.Sign(rr, r)

			if status := rr.Code; status != c.StatusCode {
				t.Errorf("handler returned wrong status code: got %v want %v", status, c.StatusCode)
			}

			body, err := ioutil.ReadAll(rr.Body)
			if err != nil {
				t.Errorf(err.Error())
			}

			if string(body) != c.Expected {
				t.Errorf("handler returned wrong body: got %v want %v", string(body), c.Expected)
			}
		})
	}
}

func TestGetPublicKey(t *testing.T) {
	type Case struct {
		Name       string
		StatusCode int
		Response   string
		Error      error
		Expected   string
	}

	samplePubkey := "pubkey"

	errReading := "{\"error\":\"error fetching key the request\"}\n"
	expectedRead := fmt.Sprintf("{\"public_key\":\"%s\"}\n", samplePubkey)

	cases := []Case{
		Case{Name: "Read Error", Error: errors.New("test"), StatusCode: http.StatusInternalServerError, Expected: errReading},
		Case{Name: "Normal case", StatusCode: http.StatusOK, Response: samplePubkey, Expected: expectedRead},
	}

	for _, c := range cases {
		t.Run(c.Name, func(t *testing.T) {
			sig := &FakeSignatory{
				ReadError:    c.Error,
				ReadResponse: c.Response,
			}
			srv := server.NewServer(sig, nil)
			r := httptest.NewRequest("GET", "http://irrelevant.com", nil)
			rr := httptest.NewRecorder()
			srv.GetKey(rr, r)

			if status := rr.Code; status != c.StatusCode {
				t.Errorf("handler returned wrong status code: got %v want %v", status, c.StatusCode)
			}

			body, err := ioutil.ReadAll(rr.Body)
			if err != nil {
				t.Errorf(err.Error())
			}

			if string(body) != c.Expected {
				t.Errorf("handler returned wrong body: got %v want %v", string(body), c.Expected)
			}
		})
	}
}
