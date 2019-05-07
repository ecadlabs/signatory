package vault

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/big"
	"net/http"
	"net/url"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/ecadlabs/signatory/config"
	"github.com/ecadlabs/signatory/signatory"
	uuid "github.com/satori/go.uuid"
)

// AzureVault contains the necessary information to interact with azure key vault api
type AzureVault struct {
	config *config.AzureConfig
	client HTTPClient
}

// HTTPClient interface representing a subset of http client method
type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// NewAzureVault create a new AzureVault struct according to the config
// if client is nil it will use the default http client
func NewAzureVault(config *config.AzureConfig, client HTTPClient) *AzureVault {
	var c HTTPClient
	c = http.DefaultClient
	if client != nil {
		c = client
	}
	return &AzureVault{
		config: config,
		client: c,
	}
}

// Name return the name of the vault
func Name() string {
	return "Azure"
}

func (s *AzureVault) getToken() (string, error) {
	data := url.Values{}
	data.Set("grant_type", "client_credentials")
	data.Set("client_id", s.config.ClientID)
	data.Set("client_secret", s.config.ClientSecret)
	data.Set("resource", "https://vault.azure.net")

	endpoint := fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/token", s.config.SubscriptionID)
	httpReq, err := http.NewRequest("POST", endpoint, strings.NewReader(data.Encode()))

	if err != nil {
		return "", err
	}

	httpReq.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	response, err := s.client.Do(httpReq)
	defer response.Body.Close()

	if err != nil {
		return "", err
	}

	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("Error response from the API %v", response.StatusCode)
	}

	azLoginResponse := struct {
		AccessToken string `json:"access_token"`
	}{}

	result, err := ioutil.ReadAll(response.Body)

	if err != nil {
		return "", err
	}

	json.Unmarshal(result, &azLoginResponse)

	return azLoginResponse.AccessToken, nil
}

func (s *AzureVault) keyIDFromKeyHash(keyHash string) string {
	for _, key := range s.config.Keys {
		if key.Hash == keyHash {
			return key.KeyID
		}
	}
	return ""
}

// Contains return true if the keyHash was found in Azure Key Vault
func (s *AzureVault) Contains(keyHash string) bool {
	result := s.keyIDFromKeyHash(keyHash)
	return result != ""
}

// ListPublicKeys retrieve all the public keys matching keyHash from the azure key vault rest api
func (s *AzureVault) ListPublicKeys() ([][]byte, error) {
	keys := [][]byte{}
	for _, key := range s.config.Keys {
		pubKey, err := s.GetPublicKey(key.Hash)
		if err != nil {
			return nil, err
		}

		keys = append(keys, pubKey)
	}
	return keys, nil
}

// GetPublicKey retrieve the public key matching keyHash from the azure key vault rest api
func (s *AzureVault) GetPublicKey(keyHash string) ([]byte, error) {
	keyID := s.keyIDFromKeyHash(keyHash)

	endpoint := fmt.Sprintf("%s?api-version=7.0", keyID)
	httpReq, err := http.NewRequest("GET", endpoint, bytes.NewReader([]byte{}))

	token, err := s.getToken()

	if err != nil {
		return nil, err
	}

	httpReq.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token))

	response, err := s.client.Do(httpReq)
	defer response.Body.Close()

	if err != nil {
		return nil, err
	}

	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Error response from the API %v", response.StatusCode)
	}

	azKeyResponse := struct {
		Key struct {
			X string `json:"x"`
			Y string `json:"y"`
		} `json:"key"`
	}{}

	result, err := ioutil.ReadAll(response.Body)

	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(result, &azKeyResponse)

	if err != nil {
		return nil, err
	}

	decodedX, err := base64.RawURLEncoding.DecodeString(azKeyResponse.Key.X)

	if err != nil {
		return nil, err
	}

	decodedY, err := base64.RawURLEncoding.DecodeString(azKeyResponse.Key.Y)

	if err != nil {
		return nil, err
	}

	// Convert the X and Y coordinate to a compress format
	// By the nature of elliptic curve for a given X there is two Y possible
	// The compressed for consist of a first byte indicating which Y was chosen
	yInt := new(big.Int).SetBytes(decodedY)
	two := new(big.Int).SetInt64(2)
	even := new(big.Int).Mod(yInt, two).CmpAbs(new(big.Int).SetInt64(0)) == 0

	pubKey := []byte{0x03} // Odd byte

	if even {
		pubKey = []byte{0x02} // Even byte
	}

	pubKey = append(pubKey, decodedX...)

	return pubKey, nil
}

// Sign submit a sign request to the azure keyvault api returns the decoded signature
func (s *AzureVault) Sign(digest []byte, keyHash string, alg string) ([]byte, error) {
	log.Debug("Signing in Azure vault")
	keyID := s.keyIDFromKeyHash(keyHash)

	request := struct {
		Alg   string `json:"alg"`
		Value string `json:"value"`
	}{
		Alg:   alg,
		Value: base64.RawURLEncoding.EncodeToString(digest[:]),
	}

	req, err := json.Marshal(request)

	if err != nil {
		return nil, err
	}

	endpoint := fmt.Sprintf("%s/sign?api-version=7.0", keyID)
	httpReq, err := http.NewRequest("POST", endpoint, bytes.NewReader(req))

	if err != nil {
		return nil, err
	}

	token, err := s.getToken()

	if err != nil {
		return nil, err
	}

	httpReq.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token))
	httpReq.Header.Add("Content-Type", "application/json")

	response, err := s.client.Do(httpReq)
	defer response.Body.Close()

	if err != nil {
		return nil, err
	}

	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Error response from the API %v", response.StatusCode)
	}

	azSignResponse := struct {
		KID   string `json:"kid"`
		Value string `json:"value"`
	}{}

	result, err := ioutil.ReadAll(response.Body)

	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(result, &azSignResponse)

	if err != nil {
		return nil, err
	}

	val, err := base64.RawURLEncoding.DecodeString(azSignResponse.Value)

	if err != nil {
		return nil, err
	}

	return val, nil
}

// Import use the azure key vault rest api to import a JWK
func (s *AzureVault) Import(jwk *signatory.JWK) (string, error) {
	log.Debug("Importing in Azure vault")
	type Key struct {
		signatory.JWK
		KeyOps []string `json:"key_ops"`
	}
	request := struct {
		Key Key `json:"key"`
	}{
		Key: Key{
			KeyOps: []string{
				"sign",
				"verify",
			},
		},
	}

	request.Key.X = jwk.X
	request.Key.Y = jwk.Y
	request.Key.D = jwk.D
	request.Key.KeyType = jwk.KeyType
	request.Key.Curve = jwk.Curve

	req, err := json.Marshal(request)

	if err != nil {
		return "", err
	}

	id := uuid.NewV4()

	if err != nil {
		return "", err
	}

	keyID := fmt.Sprintf("https://tezos.vault.azure.net/keys/%v", id)

	endpoint := fmt.Sprintf("%s?api-version=7.0", keyID)
	httpReq, err := http.NewRequest("PUT", endpoint, bytes.NewReader(req))

	if err != nil {
		return "", err
	}

	token, err := s.getToken()

	if err != nil {
		return "", err
	}

	httpReq.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token))
	httpReq.Header.Add("Content-Type", "application/json")

	response, err := s.client.Do(httpReq)
	defer response.Body.Close()

	if err != nil {
		return "", err
	}

	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("Error response from the API %v", response.StatusCode)
	}

	azImportResponse := struct {
		Key struct {
			KID string `json:"kid"`
		} `json:"key"`
	}{}

	result, err := ioutil.ReadAll(response.Body)

	if err != nil {
		return "", err
	}

	err = json.Unmarshal(result, &azImportResponse)

	if err != nil {
		return "", err
	}

	return azImportResponse.Key.KID, nil
}
