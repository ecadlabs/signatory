package file

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	config "github.com/ecadlabs/signatory/pkg/config"
	"github.com/ecadlabs/signatory/pkg/errors"
	"github.com/ecadlabs/signatory/pkg/utils"
	"github.com/ecadlabs/signatory/pkg/vault"
	"github.com/ecadlabs/signatory/pkg/vault/memory"
	"gopkg.in/yaml.v3"
)

type cfg struct {
	File string `yaml:"file"`
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
	vault.RegisterVault("file", func(ctx context.Context, node *yaml.Node, global config.GlobalContext) (vault.Vault, error) {
		if node == nil {
			return nil, errors.New("(File): config is missing")
		}
		var path string
		if node.Kind == yaml.ScalarNode {
			if err := node.Decode(&path); err != nil {
				return nil, err
			}
		} else {
			var conf cfg
			if err := node.Decode(&conf); err != nil {
				return nil, err
			}
			path = conf.File
		}
		if path == "" {
			return nil, errors.New("(File): config is missing")
		}
		path = os.ExpandEnv(path)

		if err := utils.CheckFileReadable(path); err != nil {
			return nil, fmt.Errorf("(File): %w", err)
		}

		content, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("(File): %w", err)
		}

		var entries []*tezosSecretJSONEntry
		if err := json.Unmarshal(content, &entries); err != nil {
			return nil, fmt.Errorf("(File): %w", err)
		}

		data := make([]*memory.UnparsedKey, len(entries))
		for i, e := range entries {
			data[i] = &memory.UnparsedKey{
				Data: trimSecretKey(e.Value),
				ID:   e.Name,
			}
		}
		return memory.NewUnparsed(data, "File"), nil
	})
}
