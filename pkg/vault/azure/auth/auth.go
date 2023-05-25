package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/pkcs12"
	"golang.org/x/oauth2"
)

const (
	envTenant                      = "AZURE_CLIENT_TENANT"
	envClientID                    = "AZURE_CLIENT_ID"
	envClientSecret                = "AZURE_CLIENT_SECRET"
	envClientPKCS12Certificate     = "AZURE_CLIENT_PKCS12_CERTIFICATE"
	envClientCertificate           = "AZURE_CLIENT_CERTIFICATE"
	envClientCertificateThumbprint = "AZURE_CLIENT_CERTIFICATE_THUMBPRINT"
	envPrivateKey                  = "AZURE_CLIENT_PRIVATE_KEY"
	envPrivateKeyPassword          = "AZURE_DECRYPT_PASSWORD"
)

const assertionTokenDuration = time.Hour * 24

const assertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

// Config is the configuration for using Azure authentication
type Config struct {
	Tenant                      string `yaml:"tenant_id" validate:"omitempty,uuid4"`
	ClientID                    string `yaml:"client_id" validate:"omitempty,uuid4"`
	ClientSecret                string `yaml:"client_secret"`
	ClientPKCS12Certificate     string `yaml:"client_pkcs12_certificate"`
	ClientCertificate           string `yaml:"client_certificate"`
	ClientCertificateThumbprint string `yaml:"client_certificate_thumbprint"`
	PrivateKey                  string `yaml:"client_private_key"`
	PrivateKeyPassword          string `yaml:"decrypt_password"`
}

func (c *Config) tokenURL() string {
	return fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/token", c.Tenant)
}

func (c *Config) parseEnv() *Config {
	res := *c
	if res.Tenant == "" {
		res.Tenant = os.Getenv(envTenant)
	}
	if res.ClientID == "" {
		res.ClientID = os.Getenv(envClientID)
	}
	if res.ClientSecret == "" {
		res.ClientSecret = os.Getenv(envClientSecret)
	}
	if res.ClientCertificate == "" {
		res.ClientCertificate = os.Getenv(envClientCertificate)
	}
	if res.ClientCertificateThumbprint == "" {
		res.ClientCertificateThumbprint = os.Getenv(envClientCertificateThumbprint)
	}
	if res.ClientPKCS12Certificate == "" {
		res.ClientPKCS12Certificate = os.Getenv(envClientPKCS12Certificate)
	}
	if res.PrivateKey == "" {
		res.PrivateKey = os.Getenv(envPrivateKey)
	}
	if res.PrivateKeyPassword == "" {
		res.PrivateKeyPassword = os.Getenv(envPrivateKeyPassword)
	}
	return &res
}

func parsePKCS12Certificate(name, password string) (pk interface{}, thumbprint []byte, err error) {
	buf, err := ioutil.ReadFile(name)
	if err != nil {
		return nil, nil, err
	}

	pk, cert, err := pkcs12.Decode(buf, password)
	if err != nil {
		return nil, nil, err
	}

	sum := sha1.Sum(cert.Raw)
	return pk, sum[:], nil
}

func parsePrivateKey(name, password string) (pk interface{}, err error) {
	buf, err := ioutil.ReadFile(name)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(buf)
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing the private key")
	}

	if block.Type == "RSA PRIVATE KEY" {
		var pkdata []byte
		if x509.IsEncryptedPEMBlock(block) {
			// Is it used anymore?
			pkdata, err = x509.DecryptPEMBlock(block, []byte(password))
			if err != nil {
				return nil, err
			}
		} else {
			pkdata = block.Bytes
		}
		return x509.ParsePKCS1PrivateKey(pkdata)
	}

	return x509.ParsePKCS8PrivateKey(block.Bytes) // Unencrypted PKCS#8 only
}

func getThumbprint(name string) ([]byte, error) {
	buf, err := ioutil.ReadFile(name)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(buf)
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing the certificate")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}

	sum := sha1.Sum(cert.Raw)
	return sum[:], nil
}

type jwtTokenSource struct {
	conf           *Config
	scopes         []string
	certThumbprint []byte
	key            *rsa.PrivateKey
	ctx            context.Context
}

func (c *Config) jwtTokenSource(ctx context.Context, scopes []string) (oauth2.TokenSource, error) {
	var (
		pk         interface{}
		thumbprint []byte
		err        error
	)

	if c.ClientPKCS12Certificate != "" {
		pk, thumbprint, err = parsePKCS12Certificate(c.ClientPKCS12Certificate, c.PrivateKeyPassword)
		if err != nil {
			return nil, err
		}

	} else {
		pk, err = parsePrivateKey(c.PrivateKey, c.PrivateKeyPassword)
		if err != nil {
			return nil, err
		}

		if c.ClientCertificate != "" {
			thumbprint, err = getThumbprint(c.ClientCertificate)
			if err != nil {
				return nil, err
			}

		} else {
			thumbprint, err = hex.DecodeString(c.ClientCertificateThumbprint)
			if err != nil || len(thumbprint) != sha1.Size {
				thumbprint, err = base64.URLEncoding.DecodeString(c.ClientCertificateThumbprint)
				if err != nil || len(thumbprint) != sha1.Size {
					return nil, errors.New("failed to decode thumbprint string")
				}
			}
		}
	}

	key, ok := pk.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("not a RSA key: %T", pk)
	}

	return &jwtTokenSource{
		conf:           c,
		scopes:         scopes,
		certThumbprint: thumbprint,
		key:            key,
		ctx:            ctx,
	}, nil
}

func fetchToken(ctx context.Context, url string, v url.Values) (*oauth2.Token, error) {
	client := oauth2.NewClient(ctx, nil)
	resp, err := client.PostForm(url, v)
	if err != nil {
		return nil, fmt.Errorf("auth: cannot fetch token: %w", err)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("auth: cannot fetch token: %w", err)
	}

	if resp.StatusCode/100 != 2 {
		return nil, &oauth2.RetrieveError{
			Response: resp,
			Body:     body,
		}
	}

	var res struct {
		TokenType   string `json:"token_type"`
		ExpiresIn   int64  `json:"expires_in"`
		AccessToken string `json:"access_token"`
	}

	if err := json.Unmarshal(body, &res); err != nil {
		return nil, fmt.Errorf("auth: cannot fetch token: %w", err)
	}

	token := oauth2.Token{
		AccessToken: res.AccessToken,
		TokenType:   res.TokenType,
	}
	if res.ExpiresIn > 0 {
		token.Expiry = time.Now().Add(time.Duration(res.ExpiresIn) * time.Second)
	}

	var (
		p      jwt.Parser
		claims jwt.Claims
	)
	if _, _, err := p.ParseUnverified(res.AccessToken, claims); err == nil {
		exp, err := claims.GetExpirationTime()
		if err != nil {
			return nil, fmt.Errorf("auth: cannot fetch expiration time: %v", err)
		} else {
			token.Expiry = exp.Time
		}
	}
	return &token, nil
}

// https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-client-creds-grant-flow
func (j *jwtTokenSource) Token() (*oauth2.Token, error) {
	jti := make([]byte, 20)
	_, err := rand.Read(jti)
	if err != nil {
		return nil, fmt.Errorf("auth: %w", err)
	}

	now := time.Now()

	claims := jwt.MapClaims{
		"aud": j.conf.tokenURL(),
		"iss": j.conf.ClientID,
		"sub": j.conf.ClientID,
		"jti": base64.RawURLEncoding.EncodeToString(jti),
		"nbf": now.Unix(),
		"exp": now.Add(assertionTokenDuration).Unix(),
	}

	assertionToken := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)

	kid := base64.RawURLEncoding.EncodeToString(j.certThumbprint)
	assertionToken.Header["kid"] = kid
	assertionToken.Header["x5t"] = kid

	assertion, err := assertionToken.SignedString(j.key)
	if err != nil {
		return nil, fmt.Errorf("auth: %w", err)
	}

	v := url.Values{
		"client_id":             []string{j.conf.ClientID},
		"scope":                 []string{strings.Join(j.scopes, " ")},
		"client_assertion_type": []string{assertionType},
		"client_assertion":      []string{assertion},
		"grant_type":            []string{"client_credentials"},
	}

	return fetchToken(j.ctx, j.conf.tokenURL(), v)
}

type clientSecretTokenSource struct {
	conf   *Config
	scopes []string
	ctx    context.Context
}

func (c *clientSecretTokenSource) Token() (*oauth2.Token, error) {
	v := url.Values{
		"client_id":     []string{c.conf.ClientID},
		"scope":         []string{strings.Join(c.scopes, " ")},
		"grant_type":    []string{"client_credentials"},
		"client_secret": []string{c.conf.ClientSecret},
	}

	return fetchToken(c.ctx, c.conf.tokenURL(), v)
}

// TokenSource returns new token source using the configuration.
func (c *Config) TokenSource(ctx context.Context, scopes []string) (ts oauth2.TokenSource, err error) {
	if c.ClientSecret != "" {
		ts = &clientSecretTokenSource{
			conf:   c,
			scopes: scopes,
			ctx:    ctx,
		}
	} else if ts, err = c.jwtTokenSource(ctx, scopes); err != nil {
		return nil, fmt.Errorf("auth: %w", err)
	}

	return oauth2.ReuseTokenSource(nil, ts), nil
}

// Client returns an HTTP client wrapping the context's
// HTTP transport and adding Authorization headers with tokens
// obtained from c.
func (c *Config) Client(ctx context.Context, scopes []string) (*http.Client, error) {
	ts, err := c.TokenSource(ctx, scopes)
	if err != nil {
		return nil, err
	}
	return oauth2.NewClient(ctx, ts), nil
}
