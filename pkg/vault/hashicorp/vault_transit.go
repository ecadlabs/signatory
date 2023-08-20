package hashicorp

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/ecadlabs/signatory/pkg/vault"
	"github.com/hashicorp/vault/api"
)

type TransitConfig struct {
	MountPoint string `yaml:"mountPoint"`
}

type Transit struct {
	c   *api.Client
	cfg *TransitConfig
}

type SignOpts struct {
	Preshashed bool
	Hash       string
}

func (v *Vault) Transit() *Transit {
	v.login()
	return &Transit{c: v.client, cfg: v.transitCfg}
}

func (t *Transit) ListKeys() ([]string, error) {
	var res []string
	s, err := t.c.Logical().List(fmt.Sprintf("%s/keys", t.cfg.MountPoint))
	if err != nil {
		return res, err
	}
	if s == nil {
		return res, fmt.Errorf("no key was returned")
	}

	keys, ok := s.Data["keys"].([]interface{})
	if !ok {
		return res, fmt.Errorf("failed to parse keys")
	}

	// excluding 'import' path as it's not a key and used for storing imported keys
	res = make([]string, 0, len(keys)-1)
	for _, key := range keys {
		keyStr := key.(string)
		if keyStr == "import/" {
			continue
		}
		res = append(res, keyStr)
	}

	return res, nil
}

func (t *Transit) GetKey(keyID string) (string, error) {
	return t.getKey(context.Background(), keyID)
}

func (t *Transit) GetKeyWithContext(ctx context.Context, keyID string) (string, error) {
	return t.getKey(ctx, keyID)
}

func (t *Transit) getKey(ctx context.Context, keyID string) (string, error) {
	s, err := t.c.Logical().ReadWithContext(ctx, fmt.Sprintf("%s/keys/%s", t.cfg.MountPoint, keyID))
	if err != nil {
		return "", err
	}
	if s == nil {
		return "", fmt.Errorf("no key was returned")
	}

	var pubKeyStr string

	switch s.Data["type"].(string) {
	case "ed25519":
		keys, ok := s.Data["keys"].(map[string]interface{})
		if !ok {
			return "", fmt.Errorf("failed to parse keys")
		}

		k := keys["1"].(map[string]interface{})
		pubKeyStr, ok = k["public_key"].(string)
		if !ok {
			return "", fmt.Errorf("failed to parse public key")
		}
	default:
		return "", vault.ErrKey
	}

	return pubKeyStr, nil
}

func (t *Transit) Sign(keyName string, input []byte, opts *SignOpts) ([]byte, error) {
	s, err := t.c.Logical().Write(fmt.Sprintf("%s/sign/%s", t.cfg.MountPoint, keyName), map[string]interface{}{
		"input":          base64.StdEncoding.EncodeToString(input),
		"prehashed":      opts.Preshashed,
		"hash_algorithm": opts.Hash,
	})
	if err != nil {
		return nil, err
	}
	if s == nil {
		return nil, fmt.Errorf("no signature was returned")
	}

	splitted := strings.Split(s.Data["signature"].(string), ":")
	signature, err := base64.StdEncoding.DecodeString(splitted[len(splitted)-1])
	if err != nil {
		return nil, fmt.Errorf("failed to decode signature")
	}

	return signature, nil
}

func (t *Transit) Verify(keyName string, input []byte, signature []byte, opts *SignOpts) (bool, error) {
	s, err := t.c.Logical().Write(fmt.Sprintf("%s/verify/%s", t.cfg.MountPoint, keyName), map[string]interface{}{
		"input":          base64.StdEncoding.EncodeToString(input),
		"signature":      fmt.Sprintf("vault:v1:%s", base64.StdEncoding.EncodeToString(signature)),
		"prehashed":      opts.Preshashed,
		"hash_algorithm": opts.Hash,
	})
	if err != nil {
		return false, err
	}
	if s == nil {
		return false, fmt.Errorf("no signature was returned")
	}
	return s.Data["valid"].(bool), nil
}
