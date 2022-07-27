package commands

import (
	"os"

	"github.com/spf13/cobra"
)

func NewListCommand(c *Context) *cobra.Command {
	listCmd := &cobra.Command{
		Use:   "list",
		Short: "List public keys",
		RunE: func(cmd *cobra.Command, args []string) error {
			return listKeys(c.signatory, os.Stdout, c.Context)
		},
	}

	return listCmd
}
