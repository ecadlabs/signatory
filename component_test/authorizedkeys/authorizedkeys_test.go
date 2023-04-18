package componenttest

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"testing"

	"github.com/ecadlabs/signatory/pkg/crypt"
)

const (
	url = "http://localhost:6732/keys/tz1WGcYos3hL7GXYXjKrMnSFdkT7FyXnFBvf"
)

func request_sign(body string, signature string) (int, []byte) {
	reqbody := strings.NewReader(body)
	client := &http.Client{}
	req, err := http.NewRequest(http.MethodPost, url+"?authentication="+signature, reqbody)
	if err != nil {
		log.Fatal(err)
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
	fmt.Println(string(bytes))
	return resp.StatusCode, bytes
}

func sign(message []byte) string {
	seed := []byte("this is a seed phrase for a test of Signatory")
	private := crypt.Ed25519PrivateKey(ed25519.NewKeyFromSeed(seed[:32]))
	fmt.Println("public key is " + private.Public().String())
	fmt.Println("pkh is " + private.Public().Hash().String())
	signature, err := private.Sign(message)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("signature is " + string(signature.ToProtocol().ToBase58()))
	return string(signature.ToProtocol().ToBase58())
}
func TestIt(t *testing.T) {
	request := "\"11b3d79f99000000020130c1cb51f36daebee85fe99c04800a38e8133ffd2fa329cd4db35f32fe5bf5e30000000064277aa504683625c2445a4e9564bf710c5528fd99a7d150d2a2a323bc22ff9e2710da4f6d00000021000000010200000004000000020000000000000004ffffffff0000000400000000080966c1f5a955161345bc7d81ac205ebafc89f5977a5bc88e47ab1b6f8d791e5ae8b92d9bc0523b3e07848458e66dc4265e29f3c5d8007447862e2483fdad1200000000a40d1a28000000000002\""
	unquoted := "11b3d79f99000000020130c1cb51f36daebee85fe99c04800a38e8133ffd2fa329cd4db35f32fe5bf5e30000000064277aa504683625c2445a4e9564bf710c5528fd99a7d150d2a2a323bc22ff9e2710da4f6d00000021000000010200000004000000020000000000000004ffffffff0000000400000000080966c1f5a955161345bc7d81ac205ebafc89f5977a5bc88e47ab1b6f8d791e5ae8b92d9bc0523b3e07848458e66dc4265e29f3c5d8007447862e2483fdad1200000000a40d1a28000000000002"
	dec, err := hex.DecodeString(unquoted)
	if err != nil {
		log.Fatal(err)
	}
	signature := sign(dec)
	request_sign(request, signature)
}
