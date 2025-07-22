package commands

import (
	"os"
	"slices"
	"text/template"

	proto "github.com/ecadlabs/gotez/v2/protocol/latest"
	"github.com/ecadlabs/gotez/v2/protocol/smartrollups/etherlink"
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
			kinds := proto.ListSignRequests()
			kinds = append(kinds,
				(&etherlink.UnsignedSequencerBlueprint{}).SignRequestKind(),
				etherlink.UnsignedDALSlotSignals{}.SignRequestKind(),
			)
			slices.Sort(kinds)
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
			ops := proto.ListOperations()
			ops = append(ops, proto.ListPseudoOperations()...)
			slices.Sort(ops)
			return listOpsTpl.Execute(os.Stdout, ops)
		},
	}

	return cmd
}
