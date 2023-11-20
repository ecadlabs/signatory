package commands

import (
	"context"
	"io"
	"text/template"

	"github.com/ecadlabs/signatory/pkg/tezos"
)

const listTemplateSrc = `{{range . -}}
Public Key Hash:    {{.PublicKeyHash}}
Vault:              {{.VaultName}}
ID:                 {{.ID}}
Active:             {{.Active}}
{{with .Policy -}}
Allowed Requests:   {{.AllowedRequests}}
Allowed Operations: {{.AllowedOps}}
{{end}}
{{end -}}
`

var (
	listTpl = template.Must(template.New("list").Parse(listTemplateSrc))
)

func listKeys(s *tezos.Signatory, w io.Writer, ctx context.Context) error {
	keys, err := s.ListPublicKeys(ctx)
	if err != nil {
		return err
	}
	return listTpl.Execute(w, keys)
}
