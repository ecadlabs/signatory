package commands

import (
	"os"
	"sort"
	"text/template"

	"github.com/ecadlabs/gotez/v2/encoding"
	proto "github.com/ecadlabs/gotez/v2/protocol/latest"
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
			var kinds []string
			for _, k := range encoding.ListVariants[proto.SignRequest]() {
				kinds = append(kinds, k.SignRequestKind())
			}
			sort.Strings(kinds)
			return listReqTpl.Execute(os.Stdout, kinds)
		},
	}

	return cmd
}

func NewListOps(c *Context) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list-ops",
		Short: "Print possible operation types inside the `generic` request",
		RunE: func(cmd *cobra.Command, args []string) error {
			var ops []string
			for _, k := range proto.ListOperations() {
				ops = append(ops, k.OperationKind())
			}
			for _, op := range proto.ListPseudoOperations() {
				ops = append(ops, op.PseudoOperation())
			}
			sort.Strings(ops)
			return listOpsTpl.Execute(os.Stdout, ops)
		},
	}

	return cmd
}
