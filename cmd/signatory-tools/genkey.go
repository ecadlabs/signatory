package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"os"
	"text/template"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/ecadlabs/goblst/minpk"
	"github.com/ecadlabs/signatory/pkg/crypt"
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
	PrivateKey crypt.PrivateKey
	PublicKey  crypt.PublicKey
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
					priv crypt.PrivateKey
					err  error
				)

				switch keyType {
				case "ed25519":
					var k ed25519.PrivateKey
					_, k, err = ed25519.GenerateKey(rand.Reader)
					priv = crypt.Ed25519PrivateKey(k)
				case "secp256k1":
					var k *ecdsa.PrivateKey
					k, err = ecdsa.GenerateKey(secp256k1.S256(), rand.Reader)
					priv = (*crypt.ECDSAPrivateKey)(k)
				case "p256":
					var k *ecdsa.PrivateKey
					k, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
					priv = (*crypt.ECDSAPrivateKey)(k)
				case "bls":
					var k *minpk.PrivateKey
					k, err = minpk.GenerateKey(rand.Reader)
					priv = (*crypt.BLSPrivateKey)(k)
				default:
					err = fmt.Errorf("unknown key type: %s", keyType)
				}

				if err != nil {
					return err
				}

				data = append(data, &tplData{
					PrivateKey: priv,
					PublicKey:  priv.Public(),
				})
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
