package commands

import (
	"fmt"
	"syscall"

	"github.com/ecadlabs/signatory/pkg/utils"
	"github.com/spf13/cobra"
	terminal "golang.org/x/term"
)

func NewImportCommand(c *Context) *cobra.Command {
	var (
		vaultName string
		password  string
		opt       string
	)

	importCmd := &cobra.Command{
		Use:   "import <secret-key>",
		Short: "Import Tezos private keys (edsk..., spsk..., p2sk...)",
		Args:  cobra.MinimumNArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {
			o, err := utils.ParseMap(opt, ':', ',')
			if err != nil {
				return err
			}

			var passCB func() ([]byte, error)
			if password != "" {
				passCB = func() ([]byte, error) { return []byte(password), nil }
			} else {
				passCB = func() ([]byte, error) {
					fmt.Println()
					fmt.Print("Enter Password: ")
					return terminal.ReadPassword(int(syscall.Stdin))
				}
			}

			options := make(utils.Options)
			for k, v := range o {
				options[k] = v
			}

			fmt.Print("Enter secret key: ")
			key, err := terminal.ReadPassword(int(syscall.Stdin))
			if err != nil {
				return err
			}
			fmt.Println()
			if len(key) == 0 {
				return fmt.Errorf("enter a valid secret key")
			}

			_, err = c.signatory.Import(c.Context, vaultName, string(key), passCB, options)
			if err != nil {
				return err
			}

			return nil
		},
	}

	importCmd.Flags().StringVar(&vaultName, "vault", "", "Vault name for importing")
	importCmd.Flags().StringVar(&password, "password", "", "Password for private key(s)")
	importCmd.Flags().StringVarP(&opt, "opt", "o", "", "Options to be passed to the backend. Syntax: key:val[,...]")
	cobra.MarkFlagRequired(importCmd.Flags(), "vault")

	return importCmd
}
