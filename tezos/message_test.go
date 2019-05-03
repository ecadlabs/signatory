package tezos_test

import (
	"fmt"
	"testing"

	"github.com/ecadlabs/signatory/tezos"
)

func TestValidateMessage(t *testing.T) {
	type Case struct {
		Name    string
		Message []byte
		Error   error
	}

	cases := []Case{
		Case{Name: "Nil message", Message: nil, Error: tezos.ErrMessageEmpty},
		Case{Name: "Empty message", Message: []byte{}, Error: tezos.ErrMessageEmpty},
		Case{Name: "Generic operation", Message: []byte{0x03, 0x02}, Error: nil},
		Case{Name: "Endorsement operation", Message: []byte{0x02, 0x02}, Error: nil},
		Case{Name: "Block operation", Message: []byte{0x01, 0x02}, Error: nil},
		Case{Name: "Invalid magic byte", Message: []byte{0x00, 0x02}, Error: tezos.ErrInvalidMagicByte},
		Case{Name: "Invalid magic byte", Message: []byte{0x04, 0x02}, Error: tezos.ErrInvalidMagicByte},
	}

	for _, c := range cases {
		err := tezos.ValidateMessage(c.Message)

		if err != c.Error {
			fmt.Printf("%s: Expected %v but got %v\n", c.Name, c.Error, err)
			t.Fail()
		}
	}
}
