package commands

import (
	"context"
	"io"
	"text/template"

	"github.com/ecadlabs/signatory/pkg/signatory"
	"github.com/ecadlabs/signatory/pkg/vault"
)

const listTemplateSrc = `{{range . -}}
Public Key Hash:    {{.Hash}}
Reference:          {{keyRef .KeyReference}}
Vault:              {{.Vault.Name}}
Active:             {{.Active}}
{{with .Policy -}}
Allowed Requests:   {{.AllowedRequests}}
Allowed Operations: {{.AllowedOps}}
{{end}}
{{end -}}
`

var (
	listTpl = template.Must(template.New("list").Funcs(template.FuncMap{
		"keyRef": func(ref vault.KeyReference) string {
			if withID, ok := ref.(vault.WithID); ok {
				return withID.ID()
			}
			return ""
		},
	}).Parse(listTemplateSrc))
)

func listKeys(s *signatory.Signatory, w io.Writer, ctx context.Context) error {
	keys, err := s.ListPublicKeys(ctx)
	if err != nil {
		return err
	}
	return listTpl.Execute(w, keys)
}
