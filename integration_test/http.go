package integrationtest

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

type SignSuccessResponse struct {
	Signature string `json:"signature"`
}

type SignFailureResponse struct {
	Id   string `json:"id"`
	Kind string `json:"kind"`
	Msg  string `json:"msg"`
}

func RequestSignature(pkh string, body string) (int, []byte) {
	url := "http://localhost:6732/keys/" + pkh
	reqbody := strings.NewReader(body)
	client := &http.Client{}
	req, err := http.NewRequest(http.MethodPost, url, reqbody)
	if err != nil {
		panic(err)
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

type GetKeySuccessResponse struct {
	PublicKey string `json:"public_key"`
}

func getPublicKey(pkh string) (int, []byte) {
	url := "http://localhost:6732/keys/" + pkh
	client := &http.Client{}
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		panic(err)
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

func GetPublicKey(pkh string) string {
	code, message := getPublicKey(pkh)
	if code != 200 {
		panic("GetPublicKey: http return code " + fmt.Sprint(code))
	}
	var r GetKeySuccessResponse
	dec := json.NewDecoder(bytes.NewReader(message))
	err := dec.Decode(&r)
	if err != nil {
		panic("GetPublicKey: error decoding json response: " + err.Error())
	}
	return r.PublicKey
}
