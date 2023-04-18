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
	"github.com/ecadlabs/signatory/pkg/signatory"
	"github.com/stretchr/testify/require"
)

const (
	url = "http://localhost:6732/keys/tz1QgHGuotVTCmYtA2Mr83FdiWLbwKqUvdnp"
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
	client_private := crypt.Ed25519PrivateKey(ed25519.NewKeyFromSeed(seed[:32]))
	//fmt.Println("public key is " + client_private.Public().String())
	//fmt.Println("pkh is " + client_private.Public().Hash().String())

	seed1 := []byte("yet another phrase used for seed in a test of Signatory")
	vaulted_private := crypt.Ed25519PrivateKey(ed25519.NewKeyFromSeed(seed1[:32]))
	//fmt.Println("test setup:")
	//fmt.Println("public key is " + vaulted_private.Public().String())
	//fmt.Println("pkh is " + vaulted_private.Public().Hash().String())
	//fmt.Println("private key is " + vaulted_private.String())

	sr := signatory.SignRequest{
		Message:       message,
		PublicKeyHash: vaulted_private.Public().Hash(),
	}
	bytes2sign, err := signatory.AuthenticatedBytesToSign(&sr)
	if err != nil {
		log.Fatal(err)
	}

	signature, err := client_private.Sign(bytes2sign)
	if err != nil {
		log.Fatal(err)
	}
	return string(signature.ToProtocol().ToBase58())
}

func TestIt(t *testing.T) {
	request := "\"039d3cc1568fe7c75d862bdd7af38427461133e5ec0823f14dac66653124b358b96c003745a240e6ed1bec1ef3434069c67ba2acdcc326df0201e90700c0843d00006b82198cb179e8306c1bedd08f12dc863f32888600\""
	unquoted := "039d3cc1568fe7c75d862bdd7af38427461133e5ec0823f14dac66653124b358b96c003745a240e6ed1bec1ef3434069c67ba2acdcc326df0201e90700c0843d00006b82198cb179e8306c1bedd08f12dc863f32888600"
	dec, err := hex.DecodeString(unquoted)
	require.NoError(t, err)
	signature := sign(dec)
	code, bytes := request_sign(request, signature)
	require.Equal(t, http.StatusOK, code)
	require.Contains(t, string(bytes), "signature")
}
