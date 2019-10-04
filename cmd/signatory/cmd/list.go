package cmd

import (
	"os"
	"text/template"

	"github.com/spf13/cobra"
)

const listTemplateSrc = `{{range . -}}
Public Key Hash:    {{.PublicKeyHash}}
Vault:              {{.VaultName}}
ID:                 {{.ID}}
{{with .Policy -}}
Allowed Operations: {{.AllowedOperations}}
Allowed Kinds:      {{.AllowedKinds}}
{{else - }}
*DISABLED*
{{end}}
{{end -}}
`

var (
	listTpl = template.Must(template.New("list").Parse(listTemplateSrc))
)

func newListCommand(c *rootContext) *cobra.Command {
	listCmd := &cobra.Command{
		Use:   "list",
		Short: "List public keys",
		RunE: func(cmd *cobra.Command, args []string) error {
			keys, err := c.signatory.ListPublicKeys(c.context)
			if err != nil {
				return err
			}

			return listTpl.Execute(os.Stdout, keys)
		},
	}

	return listCmd
}
