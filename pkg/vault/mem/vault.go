package file

import (
	"context"

	"github.com/ecadlabs/signatory/pkg/cryptoutils"
	"github.com/ecadlabs/signatory/pkg/errors"
	"github.com/ecadlabs/signatory/pkg/utils"
	"github.com/ecadlabs/signatory/pkg/vault"
	"github.com/ecadlabs/signatory/pkg/vault/memory"
	"gopkg.in/yaml.v3"
)

type Vault struct {
	*memory.Vault
}

func (v *Vault) Import(ctx context.Context, pk cryptoutils.PrivateKey, opt utils.Options) (vault.StoredKey, error) {
	return v.ImportKey(ctx, pk, opt)
}

func init() {
	vault.RegisterVault("mem", func(ctx context.Context, node *yaml.Node) (vault.Vault, error) {
		var conf []string
		if node == nil || node.Kind == 0 {
			return nil, errors.New("(Mem): config is missing")
		}
		if err := node.Decode(&conf); err != nil {
			return nil, err
		}

		data := make([]*memory.UnparsedKey, len(conf))
		for i, v := range conf {
			data[i] = &memory.UnparsedKey{Data: v}
		}
		return &Vault{Vault: memory.NewUnparsed(data, "Mem")}, nil
	})
}

var _ vault.Importer = (*Vault)(nil)
