package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"os"
	"text/template"

	"github.com/ecadlabs/signatory/pkg/cryptoutils"
	"github.com/ecadlabs/signatory/pkg/tezos"
	"github.com/spf13/cobra"
)

const genkeyTemplateSrc = `{{range . -}}
Private Key:     {{.PrivateKey}}
Public Key:      {{.PublicKey}}
Public Key Hash: {{.PublicKeyHash}}

{{end}}
`

var (
	genkeyTpl = template.Must(template.New("list").Parse(genkeyTemplateSrc))
)

type tplData struct {
	PrivateKey    string
	PublicKey     string
	PublicKeyHash string
}

func NewGenKeyCommand() *cobra.Command {
	var (
		keyType string
		num     int
	)

	cmd := &cobra.Command{
		Use:   "gen-key",
		Short: "Generate a key pair",
		RunE: func(cmd *cobra.Command, args []string) error {
			var data []*tplData
			for i := 0; i < num; i++ {
				var (
					pk  cryptoutils.PrivateKey
					err error
				)

				switch keyType {
				case "edsk":
					_, pk, err = ed25519.GenerateKey(rand.Reader)
				case "spsk":
					pk, err = ecdsa.GenerateKey(cryptoutils.S256(), rand.Reader)
				case "p2sk":
					pk, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				default:
					err = fmt.Errorf("unknown key type: %s", keyType)
				}

				if err != nil {
					return err
				}

				var d tplData
				if d.PrivateKey, err = tezos.EncodePrivateKey(pk); err != nil {
					return err
				}
				if d.PublicKey, err = tezos.EncodePublicKey(pk.Public()); err != nil {
					return err
				}
				if d.PublicKeyHash, err = tezos.EncodePublicKeyHash(pk.Public()); err != nil {
					return err
				}
				data = append(data, &d)
			}

			if err := genkeyTpl.Execute(os.Stdout, data); err != nil {
				return err
			}

			return nil
		},
	}

	cmd.Flags().IntVar(&num, "n", 1, "Number of key pairs to generate")
	cmd.Flags().StringVar(&keyType, "t", "edsk", "Key type [edsk, spsk, p2sk]")

	return cmd
}
