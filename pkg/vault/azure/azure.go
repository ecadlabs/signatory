package azure

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httputil"
	"net/url"
	"path"

	"github.com/ecadlabs/signatory/pkg/config"
	"github.com/ecadlabs/signatory/pkg/cryptoutils"
	"github.com/ecadlabs/signatory/pkg/errors"
	"github.com/ecadlabs/signatory/pkg/vault"
	"github.com/ecadlabs/signatory/pkg/vault/azure/auth"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
)

const apiVersion = "7.0"

var scopes = []string{"https://vault.azure.net/.default"}

// Config contains Azure KeyVault backend configuration
type Config struct {
	auth.Config `yaml:",inline"`
	Vault       string `yaml:"vault" validate:"required,url"`
}

// Vault is a Azure KeyVault backend
type Vault struct {
	client *http.Client
	config *Config
}

type azureKey struct {
	bundle *keyBundle
	pub    *ecdsa.PublicKey
}

func (a *azureKey) PublicKey() crypto.PublicKey { return a.pub }
func (a *azureKey) ID() string                  { return a.bundle.Key.KeyID }

// NewVault creates new Azure KeyVault backend
func NewVault(ctx context.Context, config *Config) (*Vault, error) {
	client, err := config.Client(context.Background(), scopes)
	if err != nil {
		return nil, fmt.Errorf("(Azure/%s): %v", config.Vault, err)
	}

	return &Vault{
		client: client,
		config: config,
	}, nil
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
		"api-version": []string{apiVersion},
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

func (v *Vault) request(ctx context.Context, method, url string, body io.Reader, result interface{}) (status int, err error) {
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return status, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json; charset=utf-8")
	}

	res, err := v.client.Do(req)
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

func (a *azureIterator) Next() (key vault.StoredKey, err error) {
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
						return nil, fmt.Errorf("(Azure/%s): %v", a.v.config.Vault, err)
					}
				} else {
					u = a.list.NextLink
					if u == "" {
						a.done = true
						return nil, vault.ErrDone
					}
				}

				status, err := a.v.request(a.ctx, "GET", u, nil, &res)
				if err != nil {
					err = fmt.Errorf("(Azure/%s): %v", a.v.config.Vault, err)
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
				}
			}

			a.list = &res
			a.i = 0
		}

		u, err := a.v.makeURL(a.list.Value[a.i].KeyID, "")
		if err != nil {
			return nil, fmt.Errorf("(Azure/%s): %v", a.v.config.Vault, err)
		}
		a.i++

		var bundle keyBundle
		status, err := a.v.request(a.ctx, "GET", u, nil, &bundle)
		if err != nil {
			err = fmt.Errorf("(Azure/%s): %v", a.v.config.Vault, err)
			if status != 0 {
				err = errors.Wrap(err, status)
			}
			return nil, err
		}

		pub, err := bundle.Key.PublicKey()
		if err != nil {
			return nil, fmt.Errorf("(Azure/%s): %v", a.v.config.Vault, err)
		}

		if ecpub, ok := pub.(*ecdsa.PublicKey); ok {
			return &azureKey{
				bundle: &bundle,
				pub:    ecpub,
			}, nil
		}
	}
}

// ListPublicKeys returns a list of keys stored under the backend
func (v *Vault) ListPublicKeys(ctx context.Context) vault.StoredKeysIterator {
	return &azureIterator{
		ctx: ctx,
		v:   v,
	}
}

// GetPublicKey returns a public key by given ID
func (v *Vault) GetPublicKey(ctx context.Context, keyID string) (vault.StoredKey, error) {
	u, err := v.makeURL(keyID, "")
	if err != nil {
		return nil, fmt.Errorf("(Azure/%s): %v", v.config.Vault, err)
	}

	var bundle keyBundle
	status, err := v.request(ctx, "GET", u, nil, &bundle)
	if err != nil {
		err = fmt.Errorf("(Azure/%s): %v", v.config.Vault, err)
		if status != 0 {
			err = errors.Wrap(err, status)
		}
		return nil, err
	}

	pub, err := bundle.Key.PublicKey()
	if err != nil {
		return nil, fmt.Errorf("(Azure/%s): %v", v.config.Vault, err)
	}

	if ecpub, ok := pub.(*ecdsa.PublicKey); ok {
		return &azureKey{
			bundle: &bundle,
			pub:    ecpub,
		}, nil
	}
	return nil, fmt.Errorf("(Azure/%s): not an EC key: %T", v.config.Vault, pub)
}

// Name returns backend name
func (v *Vault) Name() string {
	return "Azure"
}

// VaultName returns vault name
func (v *Vault) VaultName() string {
	return v.config.Vault
}

// Sign performs signing operation
func (v *Vault) Sign(ctx context.Context, digest []byte, key vault.StoredKey) (sig cryptoutils.Signature, err error) {
	azureKey, ok := key.(*azureKey)
	if !ok {
		return nil, errors.Wrap(fmt.Errorf("(Azure/%s): not a Azure key: %T ", v.config.Vault, key), http.StatusBadRequest)
	}

	var req signRequest
	if req.Algorithm = algByCurveName(azureKey.bundle.Key.Curve); req.Algorithm == "" {
		return nil, errors.Wrap(fmt.Errorf("(Azure/%s): can't find corresponding signature algorithm for %s curve", v.config.Vault, azureKey.bundle.Key.Curve), http.StatusBadRequest)
	}
	req.Value = base64.RawURLEncoding.EncodeToString(digest)

	u, err := v.makeURL(azureKey.bundle.Key.KeyID, "/sign")
	if err != nil {
		return nil, fmt.Errorf("(Azure/%s): %v", v.config.Vault, err)
	}

	r, err := json.Marshal(&req)
	if err != nil {
		return nil, fmt.Errorf("(Azure/%s): %v", v.config.Vault, err)
	}

	var res keyOperationResult
	status, err := v.request(ctx, "POST", u, bytes.NewReader(r), &res)
	if err != nil {
		err = fmt.Errorf("(Azure/%s): %v", v.config.Vault, err)
		if status != 0 {
			err = errors.Wrap(err, status)
		}
		return nil, err
	}

	b, err := base64.RawURLEncoding.DecodeString(res.Value)
	if err != nil {
		return nil, fmt.Errorf("(Azure/%s): %v", v.config.Vault, err)
	}

	byteLen := (azureKey.pub.Params().BitSize + 7) >> 3
	if len(b) != byteLen*2 {
		return nil, fmt.Errorf("(Azure/%s): invalid signature size %d", v.config.Vault, len(b))
	}

	s := cryptoutils.ECDSASignature{
		R: new(big.Int).SetBytes(b[:byteLen]),
		S: new(big.Int).SetBytes(b[byteLen:]),
	}

	return &s, nil
}

func algByCurveName(name string) string {
	switch name {
	case "P-256":
		return "ES256"
	case "P-384":
		return "ES384"
	case "P-521":
		return "ES512"
	case "P-256K":
		return "ES256K"
	case "SECP256K1":
		return "ECDSA256"
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

		return NewVault(ctx, &conf)
	})
}

var _ vault.Vault = &Vault{}
