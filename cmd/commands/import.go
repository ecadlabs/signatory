package commands

import (
	"fmt"
	"syscall"

	"github.com/ecadlabs/signatory/pkg/seed"
	"github.com/ecadlabs/signatory/pkg/utils"
	"github.com/spf13/cobra"
	terminal "golang.org/x/term"
)

func NewImportCommand(c *Context) *cobra.Command {
	var (
		vaultName string
		password  string
		opt       string
		path      string
		method    string
		hmac      bool
	)

	importCmd := &cobra.Command{
		Use:   "import [flags]",
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
					fmt.Print("This key is encrypted, enter the password: ")
					return terminal.ReadPassword(int(syscall.Stdin))
				}
			}

			options := make(utils.Options)
			for k, v := range o {
				options[k] = v
			}

			fmt.Print("Enter secret key: ")
			in, err := terminal.ReadPassword(int(syscall.Stdin))
			if err != nil {
				return err
			}
			fmt.Println()
			if len(in) == 0 {
				return fmt.Errorf("enter a valid secret key")
			}

			sk, err := seed.DerivePk(in, path, method, hmac)
			if err != nil {
				return err
			}
			fmt.Println("Abi-->: ", sk)
			_, err = c.signatory.Import(c.Context, vaultName, sk, passCB, options)
			if err != nil {
				return err
			}

			return nil
		},
	}

	importCmd.Flags().StringVar(&vaultName, "vault", "", "Vault name for importing")
	importCmd.Flags().StringVar(&password, "password", "", "Password for private key(s)")
	importCmd.Flags().StringVarP(&opt, "opt", "o", "", "Options to be passed to the backend. Syntax: key:val[,...]")
	importCmd.Flags().StringVar(&path, "path", "", "Wallet derivation path")
	importCmd.Flags().StringVar(&method, "method", "", "Wallet derivation method")
	importCmd.Flags().BoolVar(&hmac, "hmac", false, "")
	cobra.MarkFlagRequired(importCmd.Flags(), "vault")

	return importCmd
}
