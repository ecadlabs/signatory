package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"flag"
	"fmt"
	"os"
	"text/template"

	"github.com/ecadlabs/signatory/pkg/cryptoutils"
	"github.com/ecadlabs/signatory/pkg/tezos"
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

func main() {
	var (
		keyType string
		num     int
	)

	flag.IntVar(&num, "n", 1, "Keys number")
	flag.StringVar(&keyType, "t", "edsk", "Key type [edsk, spsk, p2sk]")
	flag.Parse()

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
			err = fmt.Errorf("Unknown key type: %s", keyType)
		}

		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		var d tplData
		if d.PrivateKey, err = tezos.EncodePrivateKey(pk); err != nil {
			fmt.Println(err)
			os.Exit(1)

		}
		if d.PublicKey, err = tezos.EncodePublicKey(pk.Public()); err != nil {
			fmt.Println(err)
			os.Exit(1)

		}
		if d.PublicKeyHash, err = tezos.EncodePublicKeyHash(pk.Public()); err != nil {
			fmt.Println(err)
			os.Exit(1)

		}
		data = append(data, &d)
	}

	if err := genkeyTpl.Execute(os.Stdout, data); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
