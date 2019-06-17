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
	"github.com/ecadlabs/signatory/crypto"
	"github.com/ecadlabs/signatory/signatory"
	uuid "github.com/satori/go.uuid"
)

const (
	azResVault      = "https://vault.azure.net"
	azResManagement = "https://management.azure.com/"
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

// AzureKeyDetail data about azure key
type AzureKeyDetail struct {
	ID    string `json:"kid"`
	Curve string `json:"crv"`
	X     string `json:"x"`
	Y     string `json:"y"`
	KTY   string `json:"kty"`
}

// AzureKey struct that contains data about azure key and honor the StoredKey interface
type AzureKey struct {
	Key AzureKeyDetail `json:"key"`
}

// Curve retrieve the curve to be used with this key
func (az *AzureKey) Curve() string {
	if az.Key.Curve == crypto.CurveP256KAlternate {
		return crypto.CurveP256K
	}

	return az.Key.Curve
}

func (az *AzureKey) alg() string {
	switch az.Key.Curve {
	case crypto.CurveP256KAlternate:
		return crypto.SigP256KAlternate
	case crypto.CurveP256K:
		return crypto.SigP256K
	case crypto.CurveP256:
		return crypto.SigP256
	default:
		return ""
	}
}

// ID retrive the id of this key
func (az *AzureKey) ID() string {
	return az.Key.ID
}

// PublicKey retrive the public key of this key in a compressed format
func (az *AzureKey) PublicKey() []byte {
	decodedX, err := base64.RawURLEncoding.DecodeString(az.Key.X)

	if err != nil {
		return nil
	}

	decodedY, err := base64.RawURLEncoding.DecodeString(az.Key.Y)

	if err != nil {
		return nil
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
	return pubKey
}

// NewAzureVault create a new AzureVault struct according to the config
// if client is nil it will use the default http client
func NewAzureVault(config config.AzureConfig, client HTTPClient) *AzureVault {
	var c HTTPClient
	c = http.DefaultClient
	if client != nil {
		c = client
	}
	return &AzureVault{
		config: &config,
		client: c,
	}
}

func (s *AzureVault) vaultURI() string {
	return fmt.Sprintf("https://%s.vault.azure.net", s.config.Vault)
}

// Name return the name of the vault
func (s *AzureVault) Name() string {
	return "Azure"
}

func (s *AzureVault) getToken(resource string) (string, error) {
	data := url.Values{}
	data.Set("grant_type", "client_credentials")
	data.Set("client_id", s.config.ClientID)
	data.Set("client_secret", s.config.ClientSecret)
	data.Set("resource", resource)

	endpoint := fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/token", s.config.DirectoryID)
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
		return "", fmt.Errorf("(Azure/%s) Error response from the API %v", s.config.Vault, response.StatusCode)
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

// Contains return true if the keyHash was found in Azure Key Vault
func (s *AzureVault) Contains(keyID string) bool {
	for _, key := range s.config.Keys {
		if key == keyID {
			return true
		}
	}
	return false
}

// ListPublicKeys retrieve all the public keys matching keyHash from the azure key vault rest api
func (s *AzureVault) ListPublicKeys() ([]signatory.StoredKey, error) {
	endpoint := fmt.Sprintf("%s/keys?api-version=7.0", s.vaultURI())
	httpReq, err := http.NewRequest("GET", endpoint, bytes.NewReader([]byte{}))

	if err != nil {
		return nil, err
	}

	token, err := s.getToken(azResVault)

	if err != nil {
		return nil, err
	}

	httpReq.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token))
	httpReq.Header.Add("Content-Type", "application/json")

	response, err := s.client.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		result, _ := ioutil.ReadAll(response.Body)
		return nil, fmt.Errorf("(Azure/%s) Error fetching public keys: %v, %s", s.config.Vault, response.StatusCode, string(result))
	}

	azListResponse := struct {
		Values []struct {
			ID string `json:"kid"`
		} `json:"value"`
	}{}

	result, err := ioutil.ReadAll(response.Body)

	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(result, &azListResponse)

	if err != nil {
		return nil, err
	}

	keys := []signatory.StoredKey{}
	for _, key := range azListResponse.Values {
		if s.Contains(key.ID) {
			pubKey, err := s.GetPublicKey(key.ID)
			if err != nil {
				return nil, err
			}

			keys = append(keys, pubKey)
		}

	}
	return keys, nil
}

// GetPublicKey retrieve the public key matching keyID from the azure key vault rest api
func (s *AzureVault) GetPublicKey(keyID string) (signatory.StoredKey, error) {

	endpoint := fmt.Sprintf("%s?api-version=7.0", keyID)
	httpReq, err := http.NewRequest("GET", endpoint, bytes.NewReader([]byte{}))

	token, err := s.getToken(azResVault)

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
		return nil, fmt.Errorf("(Azure/%s) Error retrieving public key %v", s.config.Vault, response.StatusCode)
	}

	azKeyResponse := AzureKey{}

	result, err := ioutil.ReadAll(response.Body)

	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(result, &azKeyResponse)

	if err != nil {
		return nil, err
	}

	return &azKeyResponse, nil
}

// Sign submit a sign request to the azure keyvault api returns the decoded signature
func (s *AzureVault) Sign(digest []byte, storedKey signatory.StoredKey) ([]byte, error) {
	log.Infof("Signing operation with Azure %s vault", s.config.Vault)

	azureKey, ok := storedKey.(*AzureKey)

	if !ok {
		return nil, fmt.Errorf("(Azure/%s): Key is not of type Azure Key", s.config.Vault)
	}

	alg := azureKey.alg()
	keyID := azureKey.ID()

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

	token, err := s.getToken(azResVault)

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
		result, _ := ioutil.ReadAll(response.Body)
		return nil, fmt.Errorf("(Azure/%s) Error signing operation  %v, %s", s.config.Vault, response.StatusCode, string(result))
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

// Ready return true if the vault is ready
func (s *AzureVault) Ready() bool {
	resourceURI := url.PathEscape(
		fmt.Sprintf(
			"/subscriptions/%s/resourceGroups/%s/providers/Microsoft.KeyVault/vaults/%s",
			s.config.SubscriptionID,
			s.config.ResourceGroup,
			s.config.Vault,
		),
	)
	uri := fmt.Sprintf("https://management.azure.com/%s/providers/Microsoft.ResourceHealth/availabilityStatuses/current?api-version=2018-08-01-preview", resourceURI)

	httpReq, err := http.NewRequest("GET", uri, bytes.NewReader([]byte{}))

	token, err := s.getToken(azResManagement)

	if err != nil {
		return false
	}

	httpReq.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token))

	response, err := s.client.Do(httpReq)
	defer response.Body.Close()

	if err != nil {
		return false
	}

	if response.StatusCode != http.StatusOK {
		return false
	}

	return true
}

// Import use the azure key vault rest api to import a JWK
func (s *AzureVault) Import(jwk *signatory.JWK) (string, error) {
	log.Infof("Importing key into Azure %s vault", s.config.Vault)
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

	keyID := fmt.Sprintf("%s/keys/%v", s.vaultURI(), id)

	endpoint := fmt.Sprintf("%s?api-version=7.0", keyID)
	httpReq, err := http.NewRequest("PUT", endpoint, bytes.NewReader(req))

	if err != nil {
		return "", err
	}

	token, err := s.getToken(azResVault)

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
		result, _ := ioutil.ReadAll(response.Body)
		return "", fmt.Errorf("(Azure/%s) Error importing key %v, %s", s.config.Vault, response.StatusCode, string(result))
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
