package commands

import (
	"context"
	"io"
	"text/template"

	"github.com/ecadlabs/signatory/pkg/signatory"
)

const listTemplateSrc = `{{range . -}}
Public Key Hash:    {{.PublicKeyHash}}
Ref:                {{.}}
Vault:              {{.VaultName}}
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

func listKeys(s *signatory.Signatory, w io.Writer, ctx context.Context) error {
	keys, err := s.ListPublicKeys(ctx)
	if err != nil {
		return err
	}
	return listTpl.Execute(w, keys)
}
