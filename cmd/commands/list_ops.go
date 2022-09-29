package commands

import (
	"os"
	"text/template"

	"github.com/ecadlabs/signatory/pkg/tezos"
	"github.com/spf13/cobra"
)

const listReqTemplateSrc = `Possible request types:
{{- range .}}
    - {{.}}
{{- end}}
`

const listOpsTemplateSrc = `Possible operation types:
{{- range .}}
    - {{.}}
{{- end}}
`

var (
	listReqTpl = template.Must(template.New("list").Parse(listReqTemplateSrc))
	listOpsTpl = template.Must(template.New("list").Parse(listOpsTemplateSrc))
)

func NewListRequests(c *Context) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list-requests",
		Short: "Print possible request types",
		RunE: func(cmd *cobra.Command, args []string) error {
			return listReqTpl.Execute(os.Stdout, tezos.RequestKinds)
		},
	}

	return cmd
}

func NewListOps(c *Context) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list-ops",
		Short: "Print possible operation types inside the `generic` request",
		RunE: func(cmd *cobra.Command, args []string) error {
			return listOpsTpl.Execute(os.Stdout, tezos.Operations)
		},
	}

	return cmd
}
