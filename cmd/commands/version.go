package commands

import (
	"fmt"

	"github.com/ecadlabs/signatory/pkg/metrics"
	"github.com/spf13/cobra"
)

func NewVersionCommand(c *Context) *cobra.Command {
	listCmd := &cobra.Command{
		Use:     "version",
		Aliases: []string{"v"},
		Short:   "Show signatory image version/release (short alias 'v') ",
		RunE: func(cmd *cobra.Command, args []string) error {
			var vout string
			if metrics.GitRevision != metrics.GitBranch {
				vout = "GitRevision: " + metrics.GitRevision + "\n" + "GitBranch: " + metrics.GitBranch
			} else {
				vout = "Release Version: " + metrics.GitRevision
			}

			fmt.Println(vout)
			return nil
		},
	}

	return listCmd
}
