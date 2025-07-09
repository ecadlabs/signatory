package commands

import (
	"fmt"
	"os"

	"github.com/ecadlabs/signatory/pkg/cryptoutils"
	"github.com/spf13/cobra"
)

func NewGenerateCommand(c *Context) *cobra.Command {
	var (
		vaultName string
		keyType   string
		keysNum   int
	)

	generateCmd := &cobra.Command{
		Use:   "generate",
		Short: "Generate and store key(s) on a backend side",
		RunE: func(cmd *cobra.Command, args []string) error {
			kt := cryptoutils.KeyTypeFromString(keyType)
			if kt == nil {
				return fmt.Errorf("unknown key type: %s", keyType)
			}
			keys, err := c.signatory.Generate(c.Context, vaultName, kt, keysNum)
			if err != nil {
				return err
			}
			return listTpl.Execute(os.Stdout, keys)
		},
	}

	generateCmd.Flags().StringVarP(&vaultName, "vault", "v", "", "Vault name for importing")
	generateCmd.Flags().IntVarP(&keysNum, "num", "n", 1, "Number of keys to generate")
	generateCmd.Flags().StringVarP(&keyType, "type", "t", "ed25519", "Key algorithm: [tz1, tz2, tz3, tz4, ed25519, secp256k1, p256, bls]")
	cobra.MarkFlagRequired(generateCmd.Flags(), "vault")

	return generateCmd
}
