package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"os"
	"text/template"

	"github.com/ecadlabs/goblst/minpk"
	"github.com/ecadlabs/gotez"
	"github.com/ecadlabs/signatory/pkg/cryptoutils"
	"github.com/spf13/cobra"
)

const genkeyTemplateSrc = `{{range . -}}
Private Key:     {{.PrivateKey}}
Public Key:      {{.PublicKey}}
Public Key Hash: {{.PublicKey.Hash}}

{{end}}
`

var (
	genkeyTpl = template.Must(template.New("list").Parse(genkeyTemplateSrc))
)

type tplData struct {
	PrivateKey gotez.PrivateKey
	PublicKey  gotez.PublicKey
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
				case "ed25519":
					_, pk, err = ed25519.GenerateKey(rand.Reader)
				case "secp256k1":
					pk, err = ecdsa.GenerateKey(cryptoutils.S256(), rand.Reader)
				case "p256":
					pk, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				case "bls":
					pk, err = minpk.GenerateKey(rand.Reader)
				default:
					err = fmt.Errorf("unknown key type: %s", keyType)
				}

				if err != nil {
					return err
				}

				var d tplData
				if d.PrivateKey, err = gotez.NewPrivateKey(pk); err != nil {
					return err
				}
				if d.PublicKey, err = gotez.NewPublicKey(pk.Public()); err != nil {
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

	cmd.Flags().IntVarP(&num, "num", "n", 1, "Number of key pairs to generate")
	cmd.Flags().StringVarP(&keyType, "type", "t", "ed25519", "Key type [ed25519, secp256k1, p256, bls]")

	return cmd
}
