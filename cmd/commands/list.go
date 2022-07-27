package commands

import (
	"os"
	"text/template"

	"github.com/spf13/cobra"
)

const listTemplateSrc = `{{range . -}}
Public Key Hash:    {{.PublicKeyHash}}
Vault:              {{.VaultName}}
Publik key Path:    {{.ID}}
Active:             {{.Active}}
{{with .Policy -}}
Allowed Operations: {{.AllowedOperations}}
Allowed Kinds:      {{.AllowedKinds}}
{{end}}
{{end -}}
`

var (
	listTpl = template.Must(template.New("list").Parse(listTemplateSrc))
)

func NewListCommand(c *Context) *cobra.Command {
	listCmd := &cobra.Command{
		Use:   "list",
		Short: "List public keys",
		RunE: func(cmd *cobra.Command, args []string) error {
			keys, err := c.signatory.ListPublicKeys(c.Context)
			if err != nil {
				return err
			}

			return listTpl.Execute(os.Stdout, keys)
		},
	}

	return listCmd
}
