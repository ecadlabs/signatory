package azure

import (
	"bytes"
	"context"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httputil"
	"net/url"
	"path"
	"strings"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/ecadlabs/gotez/v2/crypt"
	"github.com/ecadlabs/signatory/pkg/config"
	"github.com/ecadlabs/signatory/pkg/errors"
	"github.com/ecadlabs/signatory/pkg/utils"
	"github.com/ecadlabs/signatory/pkg/vault"
	"github.com/ecadlabs/signatory/pkg/vault/azure/auth"
	"github.com/ecadlabs/signatory/pkg/vault/azure/jwk"
	"github.com/segmentio/ksuid"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
)

const (
	managementURL = "https://management.azure.com/"

	keyVaultAPIVersion       = "7.0"
	resourceHealthAPIVersion = "2018-08-01-rc"
)

var (
	vaultScopes      = []string{"https://vault.azure.net/.default"}
	managementScopes = []string{managementURL + ".default"}
)

// Config contains Azure KeyVault backend configuration
type Config struct {
	auth.Config    `yaml:",inline"`
	Vault          string `yaml:"vault" validate:"required,url"`
	SubscriptionID string `yaml:"subscription_id" validate:"omitempty,uuid4"` // Optional
	ResourceGroup  string `yaml:"resource_group"`                             // Optional
}

// Vault is a Azure KeyVault backend
type Vault struct {
	client           *http.Client
	managementClient *http.Client
	config           *Config
}

type azureKey struct {
	bundle *keyBundle
	pub    *crypt.ECDSAPublicKey
	v      *Vault
}

func (k *azureKey) PublicKey() crypt.PublicKey { return k.pub }
func (k *azureKey) ID() string                 { return k.bundle.Key.KeyID }
func (k *azureKey) Vault() vault.Vault         { return k.v }

func (key *azureKey) Sign(ctx context.Context, message []byte) (crypt.Signature, error) {
	digest := crypt.DigestFunc(message)
	var req signRequest
	if req.Algorithm = algByCurve(key.pub.Curve); req.Algorithm == "" {
		return nil, errors.Wrap(fmt.Errorf("(Azure/%s): can't find corresponding signature algorithm for %s curve", key.v.config.Vault, key.bundle.Key.Curve), http.StatusBadRequest)
	}
	req.Value = base64.RawURLEncoding.EncodeToString(digest[:])

	u, err := key.v.makeURL(key.bundle.Key.KeyID, "/sign")
	if err != nil {
		return nil, fmt.Errorf("(Azure/%s): %w", key.v.config.Vault, err)
	}

	r, err := json.Marshal(&req)
	if err != nil {
		return nil, fmt.Errorf("(Azure/%s): %w", key.v.config.Vault, err)
	}

	var res keyOperationResult
	status, err := key.v.request(ctx, key.v.client, "POST", u, bytes.NewReader(r), &res)
	if err != nil {
		err = fmt.Errorf("(Azure/%s): %w", key.v.config.Vault, err)
		if status != 0 {
			err = errors.Wrap(err, status)
		}
		return nil, err
	}

	sig, err := base64.RawURLEncoding.DecodeString(res.Value)
	if err != nil {
		return nil, fmt.Errorf("(Azure/%s): %w", key.v.config.Vault, err)
	}

	byteLen := (key.pub.Params().BitSize + 7) >> 3
	if len(sig) != byteLen*2 {
		return nil, fmt.Errorf("(Azure/%s): invalid signature size %d", key.v.config.Vault, len(sig))
	}
	return &crypt.ECDSASignature{
		R:     new(big.Int).SetBytes(sig[:byteLen]),
		S:     new(big.Int).SetBytes(sig[byteLen:]),
		Curve: key.pub.Curve,
	}, nil
}

// New creates new Azure KeyVault backend
func New(ctx context.Context, config *Config) (vault *Vault, err error) {
	v := Vault{
		config: config,
	}

	if v.client, err = config.Client(context.Background(), vaultScopes); err != nil {
		return nil, fmt.Errorf("(Azure/%s): %w", config.Vault, err)
	}

	if v.config.SubscriptionID != "" && v.config.ResourceGroup != "" {
		if v.managementClient, err = config.Client(context.Background(), managementScopes); err != nil {
			return nil, fmt.Errorf("(Azure/%s): %w", config.Vault, err)
		}
	}

	return &v, nil
}

func (v *Vault) makeURL(baseURL, p string) (string, error) {
	u, err := url.Parse(baseURL)
	if err != nil {
		return "", err
	}
	if p != "" {
		u.Path = path.Join(u.Path, p)
	}
	u.RawQuery = url.Values{
		"api-version": []string{keyVaultAPIVersion},
	}.Encode()
	return u.String(), nil
}

func (v *Vault) vaultError(res *http.Response) error {
	var response keyVaultErrorResponse
	dec := json.NewDecoder(res.Body)
	if err := dec.Decode(&response); err != nil {
		return err
	}

	msg := res.Status
	if response.Error != nil {
		msg = response.Error.Message
	}

	return errors.New(msg)
}

func (v *Vault) request(ctx context.Context, client *http.Client, method, url string, body io.Reader, result interface{}) (status int, err error) {
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return status, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json; charset=utf-8")
	}

	res, err := client.Do(req)
	if err != nil {
		return status, err
	}

	if log.IsLevelEnabled(log.TraceLevel) {
		dump, err := httputil.DumpResponse(res, true)
		if err != nil {
			return status, err
		}
		wr := log.StandardLogger().WriterLevel(log.TraceLevel)
		wr.Write(dump)
		wr.Write([]byte("\n"))
		wr.Close()
	}
	defer res.Body.Close()

	status = res.StatusCode
	if status/100 != 2 {
		return status, v.vaultError(res)
	}
	if status == http.StatusNoContent {
		return status, nil
	}

	dec := json.NewDecoder(res.Body)
	if err = dec.Decode(result); err != nil {
		return status, err
	}
	return status, nil
}

type azureIterator struct {
	ctx  context.Context
	v    *Vault
	list *keyListResult
	i    int
	done bool
}

func (a *azureIterator) Next() (key vault.KeyReference, err error) {
	if a.done {
		return nil, vault.ErrDone
	}

	for {
		if a.list == nil || a.i == len(a.list.Value) {
			var res keyListResult
			for {
				var u string
				if a.list == nil {
					u, err = a.v.makeURL(a.v.config.Vault, "/keys")
					if err != nil {
						return nil, fmt.Errorf("(Azure/%s): %w", a.v.config.Vault, err)
					}
				} else {
					u = a.list.NextLink
					if u == "" {
						a.done = true
						return nil, vault.ErrDone
					}
				}

				status, err := a.v.request(a.ctx, a.v.client, "GET", u, nil, &res)
				if err != nil {
					err = fmt.Errorf("(Azure/%s): %w", a.v.config.Vault, err)
					if status != 0 {
						err = errors.Wrap(err, status)
					}
					return nil, err
				}

				if status == http.StatusNoContent {
					a.done = true
					return nil, vault.ErrDone
				}

				if len(res.Value) != 0 {
					break
				} else {
					return nil, vault.ErrDone
				}
			}

			a.list = &res
			a.i = 0
		}

		u, err := a.v.makeURL(a.list.Value[a.i].KeyID, "")
		if err != nil {
			return nil, fmt.Errorf("(Azure/%s): %w", a.v.config.Vault, err)
		}
		a.i++

		var bundle keyBundle
		status, err := a.v.request(a.ctx, a.v.client, "GET", u, nil, &bundle)
		if err != nil {
			err = fmt.Errorf("(Azure/%s): %w", a.v.config.Vault, err)
			if status != 0 {
				err = errors.Wrap(err, status)
			}
			return nil, err
		}

		jwKey, err := bundle.Key.PublicKey()
		if err != nil {
			return nil, fmt.Errorf("(Azure/%s): %w", a.v.config.Vault, err)
		}
		if p, err := crypt.NewPublicKeyFrom(jwKey); err == nil {
			if pub, ok := p.(*crypt.ECDSAPublicKey); ok {
				return &azureKey{
					bundle: &bundle,
					pub:    pub,
					v:      a.v,
				}, nil
			} else {
				panic(fmt.Sprintf("unsupported key type: %T", p)) // unlikely
			}
		} else if err != crypt.ErrUnsupportedKeyType {
			return nil, fmt.Errorf("(Azure/%s): %w", a.v.config.Vault, err)
		}
	}
}

// List returns a list of keys stored under the backend
func (v *Vault) List(ctx context.Context) vault.KeyIterator {
	return &azureIterator{
		ctx: ctx,
		v:   v,
	}
}

func (v *Vault) Name() string {
	return fmt.Sprintf("Azure/%s", v.config.Vault)
}

// Import imports a private key
func (v *Vault) Import(ctx context.Context, priv crypt.PrivateKey, opt utils.Options) (vault.KeyReference, error) {
	keyName, ok, err := opt.GetString("name")
	if err != nil {
		return nil, fmt.Errorf("(Azure/%s): %w", v.config.Vault, err)
	}
	if !ok {
		keyName = "signatory-imported-" + ksuid.New().String()
	}

	ecdsaKey, ok := priv.(*crypt.ECDSAPrivateKey)
	if !ok {
		return nil, fmt.Errorf("(Azure/%s) Unsupported key type: %T", v.config.Vault, priv)
	}

	key, err := jwk.EncodePrivateKey(ecdsaKey.Unwrap())
	if err != nil {
		return nil, fmt.Errorf("(Azure/%s): %w", v.config.Vault, err)
	}

	req := importRequest{
		Key: key,
		Hsm: true,
	}

	r, err := json.Marshal(&req)
	if err != nil {
		return nil, fmt.Errorf("(Azure/%s): %w", v.config.Vault, err)
	}

	u, err := v.makeURL(v.config.Vault, "/keys/"+keyName)
	if err != nil {
		return nil, fmt.Errorf("(Azure/%s): %w", v.config.Vault, err)
	}

	var bundle keyBundle
	status, err := v.request(ctx, v.client, "PUT", u, bytes.NewReader(r), &bundle)
	if err != nil {
		err = fmt.Errorf("(Azure/%s): %w", v.config.Vault, err)
		if status != 0 {
			err = errors.Wrap(err, status)
		}
		return nil, err
	}

	jwKey, err := bundle.Key.PublicKey()
	if err != nil {
		return nil, fmt.Errorf("(Azure/%s): %w", v.config.Vault, err)
	}

	pub, err := crypt.NewPublicKeyFrom(jwKey)
	if err != nil {
		return nil, fmt.Errorf("(Azure/%s): %w", v.config.Vault, err)
	}
	if p, ok := pub.(*crypt.ECDSAPublicKey); ok {
		return &azureKey{
			bundle: &bundle,
			pub:    p,
			v:      v,
		}, nil
	} else {
		panic(fmt.Sprintf("unsupported key type: %T", pub)) // unlikely
	}
}

// Ready implements vault.ReadinessChecker
func (v *Vault) Ready(ctx context.Context) (bool, error) {
	if v.managementClient == nil {
		return true, nil // ignore
	}

	u, err := url.Parse(v.config.Vault)
	if err != nil {
		return false, err
	}
	vault := u.Host
	if s := strings.SplitN(vault, ".", 2); len(s) == 2 {
		vault = s[0]
	}

	uri := managementURL +
		"/subscriptions/" + v.config.SubscriptionID +
		"/resourceGroups/" + v.config.ResourceGroup +
		"/providers/Microsoft.KeyVault/vaults/" + vault +
		"/providers/Microsoft.ResourceHealth/availabilityStatuses/current?api-version=" + resourceHealthAPIVersion

	var res resourceHealthAvailabilityStatus
	status, err := v.request(ctx, v.managementClient, "GET", uri, nil, &res)
	if err != nil {
		err = fmt.Errorf("(Azure/%s): %w", v.config.Vault, err)
		if status != 0 {
			err = errors.Wrap(err, status)
		}
		return false, err
	}

	if res.Properties.AvailabilityState != availabilityStatusAvailable {
		return false, nil
	}

	return true, nil
}

func (v *Vault) Close(context.Context) error {
	return nil
}

func algByCurve(curve elliptic.Curve) string {
	switch curve {
	case elliptic.P256():
		return "ES256"
	case elliptic.P384():
		return "ES384"
	case elliptic.P521():
		return "ES512"
	case secp256k1.S256():
		return "ES256K" // https://github.com/Azure/azure-sdk-for-go/blob/main/sdk/security/keyvault/azkeys/constants.go
	default:
		return ""
	}
}

func init() {
	vault.RegisterVault("azure", func(ctx context.Context, node *yaml.Node) (vault.Vault, error) {
		var conf Config
		if node == nil || node.Kind == 0 {
			return nil, errors.New("(Azure): config is missing")
		}
		if err := node.Decode(&conf); err != nil {
			return nil, err
		}

		if err := config.Validator().Struct(&conf); err != nil {
			return nil, err
		}

		return New(ctx, &conf)
	})
}

var _ vault.Importer = &Vault{}
