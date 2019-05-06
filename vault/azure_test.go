package vault_test

import (
	"bytes"
	"io/ioutil"
	"net/http"
	"testing"

	"github.com/ecadlabs/signatory/config"
	"github.com/ecadlabs/signatory/vault"
)

type HandleFunc func(req *http.Request) (*http.Response, error)

type MockClient struct {
	DoFunc HandleFunc
}

func (m *MockClient) Do(req *http.Request) (*http.Response, error) {
	if m.DoFunc != nil {
		return m.DoFunc(req)
	}
	return &http.Response{}, nil
}

func mockLogin() func(req *http.Request) (*http.Response, error) {
	return func(req *http.Request) (*http.Response, error) {
		body := ioutil.NopCloser(bytes.NewBufferString(`{ "access_token" : "test"}`))
		return &http.Response{
			StatusCode: 200,
			Body:       body,
			Header:     make(http.Header),
		}, nil
	}
}

func mockSign(body string, status int) func(req *http.Request) (*http.Response, error) {
	return func(req *http.Request) (*http.Response, error) {
		body := ioutil.NopCloser(bytes.NewBufferString(body))
		return &http.Response{
			StatusCode: status,
			Body:       body,
			Header:     make(http.Header),
		}, nil
	}
}

func mockRequest(loginFunc HandleFunc, signFunc HandleFunc) func(req *http.Request) (*http.Response, error) {
	return func(req *http.Request) (*http.Response, error) {
		if req.Host == "login.microsoftonline.com" {
			return loginFunc(req)
		} else {
			return signFunc(req)
		}
	}
}

func TestAzureSign(t *testing.T) {
	do := mockRequest(mockLogin(), mockSign(`{ "kid" : "test", "value": "123455"}`, 200))
	az := vault.NewAzureVault(&config.AzureConfig{}, &MockClient{do})
	bytesToSign := []byte{0x03, 0xff, 0x33}
	sig, err := az.Sign(bytesToSign, "", "ES256")

	if err != nil {
		t.Fail()
	}

	expected := []byte{215, 109, 248, 231}
	if string(sig) != string(expected) {
		t.Fail()
	}
}

func TestAzureSignError(t *testing.T) {
	do := mockRequest(mockLogin(), mockSign(`Key not found`, 404))
	az := vault.NewAzureVault(&config.AzureConfig{}, &MockClient{do})
	bytesToSign := []byte{0x03, 0xff, 0x33}
	_, err := az.Sign(bytesToSign, "", "ES256")

	if err == nil {
		t.Fail()
	}
}
