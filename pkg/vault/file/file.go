package file

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"strings"

	config "github.com/ecadlabs/signatory/pkg/config"
	"github.com/ecadlabs/signatory/pkg/errors"
	"github.com/ecadlabs/signatory/pkg/vault"
	"github.com/ecadlabs/signatory/pkg/vault/memory"
	"gopkg.in/yaml.v3"
)

// Config contains file based backend configuration
type Config struct {
	File string `yaml:"file" validate:"required"`
}

func trimSecretKey(k string) string {
	if i := strings.IndexByte(string(k), ':'); i >= 0 {
		return string(k)[i+1:]
	}
	return string(k)
}

type tezosSecretJSONEntry struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

func init() {
	vault.RegisterVault("file", func(ctx context.Context, node *yaml.Node) (vault.Vault, error) {
		var conf Config
		if node == nil || node.Kind == 0 {
			return nil, errors.New("(File): config is missing")
		}
		if err := node.Decode(&conf); err != nil {
			return nil, err
		}

		if err := config.Validator().Struct(&conf); err != nil {
			return nil, err
		}

		content, err := ioutil.ReadFile(conf.File)
		if err != nil {
			return nil, fmt.Errorf("(File): %v", err)
		}

		var entries []*tezosSecretJSONEntry
		if err := json.Unmarshal(content, &entries); err != nil {
			return nil, fmt.Errorf("(File): %v", err)
		}

		data := make([]*memory.KeyData, len(entries))
		for i, e := range entries {
			data[i] = &memory.KeyData{
				Data: trimSecretKey(e.Value),
				ID:   e.Name,
			}
		}
		return memory.New(data, "File"), nil
	})
}
