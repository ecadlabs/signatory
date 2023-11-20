package commands

import (
	"os"
	"sort"
	"text/template"

	"github.com/ecadlabs/gotez/encoding"
	"github.com/ecadlabs/gotez/protocol"
	"github.com/ecadlabs/signatory/pkg/tezos/request"
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
			kindsMap := make(map[string]struct{})
			encoding.ForEachInEnum(func(tag uint8, req request.SignRequest) {
				kindsMap[req.RequestKind()] = struct{}{}
			})
			var kinds []string
			for k := range kindsMap {
				kinds = append(kinds, k)
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
			opsMap := make(map[string]struct{})
			encoding.ForEachInEnum(func(tag uint8, req protocol.OperationContents) {
				opsMap[req.OperationKind()] = struct{}{}
			})
			var ops []string
			for k := range opsMap {
				ops = append(ops, k)
			}
			sort.Strings(ops)
			return listOpsTpl.Execute(os.Stdout, ops)
		},
	}

	return cmd
}
