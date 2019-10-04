package cmd

import (
	"fmt"
	"syscall"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh/terminal"
)

func newImportCommand(c *rootContext) *cobra.Command {
	var (
		vaultName string
		password  string
	)

	importCmd := &cobra.Command{
		Use:   "import",
		Short: "Import Tezos private keys (edsk..., spsk..., p2sk...)",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var passCB func() ([]byte, error)
			if password != "" {
				passCB = func() ([]byte, error) { return []byte(password), nil }
			} else {
				passCB = func() ([]byte, error) {
					fmt.Print("Enter Password: ")
					return terminal.ReadPassword(int(syscall.Stdin))
				}
			}

			for _, key := range args {
				_, err := c.signatory.Import(c.context, vaultName, key, passCB)
				if err != nil {
					return err
				}
			}

			return nil
		},
	}

	importCmd.Flags().StringVar(&vaultName, "vault", "", "Vault name for importing")
	importCmd.Flags().StringVar(&password, "password", "", "Password for private key(s)")
	cobra.MarkFlagRequired(importCmd.Flags(), "vault")

	return importCmd
}
