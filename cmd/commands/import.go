package commands

import (
	"fmt"
	"os"
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
		pemFile   string
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
			options := make(utils.Options)
			for k, v := range o {
				options[k] = v
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

			var keys [][]byte
			if pemFile != "" {
				pemData, err := os.ReadFile(pemFile)
				if err != nil {
					return err
				}
				keys = [][]byte{pemData}
			} else if len(args) != 0 {
				keys = make([][]byte, len(args))
				for i, a := range args {
					keys[i] = []byte(a)
				}
			} else {
				fmt.Print("Enter the secret key: ")
				key, err := terminal.ReadPassword(int(syscall.Stdin))
				fmt.Println("")
				if err != nil {
					return err
				}
				keys = [][]byte{key}
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
	importCmd.Flags().StringVarP(&pemFile, "from", "f", "", "Import PKCS#8 PEM file")
	importCmd.Flags().StringVarP(&opt, "opt", "o", "", "Options to be passed to the backend. Syntax: key:val[,...]")
	cobra.MarkFlagRequired(importCmd.Flags(), "vault")

	return importCmd
}
