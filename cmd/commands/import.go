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
		Use:   "import [secret-key]",
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
					fmt.Print("Enter the password: ")
					pwd, err := terminal.ReadPassword(int(syscall.Stdin))
					fmt.Println("")
					return pwd, err
				}
			}

			options := make(utils.Options)
			for k, v := range o {
				options[k] = v
			}

			var keys []string
			if len(args) == 0 {
				fmt.Print("Enter the secret key: ")
				key, err := terminal.ReadPassword(int(syscall.Stdin))
				fmt.Println("")
				if err != nil {
					return err
				}
				keys = []string{string(key)}
			} else {
				keys = args
			}

			for _, key := range keys {
				_, err := c.signatory.Import(c.Context, vaultName, key, passCB, options)
				if err != nil {
					return err
				}
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
