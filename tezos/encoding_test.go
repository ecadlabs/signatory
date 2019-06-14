package tezos_test

import (
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/ecadlabs/signatory/tezos"
)

func TestEncodeSig(t *testing.T) {
	type Case struct {
		Name       string
		Signature  string
		PubkeyHash string
		Encoded    string
	}

	cases := []Case{
		Case{Name: "tz3 address", PubkeyHash: "tz3jbFvkPL3asPSYFnCsFeCzciqmtGB2GSXF", Signature: "d3995bb0def61ccb738b42496b0bd72033838c549969705a140848ae38f3d8978311861c08ad3a36ca6629623b4bfc0355bdf6235ff00947e3559cba86cd8321", Encoded: "p2sigpz98AtaPi7qA5iCLD5D99o6x2U7erhYpFKgNu6vQQZ1SCuZpxZ52CqSLyHZfVtnVEv5QZ1orbcHjMUac2dq5BvZZsn4hX"},
		Case{Name: "tz2 address", PubkeyHash: "tz2BFTyPeYRzxd5aiBchbXN3WCZhx7BqbMBq", Signature: "58e0bcb53b0fa5f26ed219cfe758e636a3b2ad8965668f316de7a58ebb98e7f45fca95fa20374fdf6b7ee33a0af5fba2bdda315584f599a269e063b6c0c5338e", Encoded: "spsig1HSPAHDd613rUxcgB1L2NJAX5kAXYtnmHTLD6axMChL93LBWzAMND5JS5aPyxHNwfLcBw6ZG45Kt1N3XhLLzeiF4DjJNHj"},
		Case{Name: "Invalid address", PubkeyHash: "tz4test", Signature: "58e0bcb53b0fa5f26ed219cfe758e636a3b2ad8965668f316de7a58ebb98e7f45fca95fa20374fdf6b7ee33a0af5fba2bdda315584f599a269e063b6c0c5338e", Encoded: ""},
	}

	for _, c := range cases {
		sigBytes, err := hex.DecodeString(c.Signature)

		if err != nil {
			t.Fail()
			return
		}

		encoded := tezos.EncodeSig(c.PubkeyHash, sigBytes)

		if encoded != c.Encoded {
			fmt.Printf("%s: Expected %v but got %v\n", c.Name, c.Encoded, encoded)
			t.Fail()
		}
	}
}

func TestEncodePubKey(t *testing.T) {
	type Case struct {
		Name       string
		PubKey     string
		PubkeyHash string
		Encoded    string
	}

	cases := []Case{
		Case{Name: "tz2 address", PubkeyHash: "tz2BFTyPeYRzxd5aiBchbXN3WCZhx7BqbMBq", PubKey: "02e732719dc5263fbf7f07400926a2e648cd10a73481423d5a587eabdb34e41586", Encoded: "sppk7b4TURq2T9rhPLFaSz6mkBCzKzfiBjctQSMorvLD5GSgCduvKuf"},
		Case{Name: "tz3 address", PubkeyHash: "tz3jbFvkPL3asPSYFnCsFeCzciqmtGB2GSXF", PubKey: "0373babb8a43d6ad35763ed917654ee704b7fae08c64042fbb9de13584c86e6cee", Encoded: "p2pk67PsiUBJZq9twKoFAWt8fSSVn53BR31dxKnTeLirLxHqB8gSnCq"},
		Case{Name: "Invalid address", PubkeyHash: "tz4jbFvkPL3asPSYFnCsFeCzciqmtGB2GSXF", PubKey: "0373babb8a43d6ad35763ed917654ee704b7fae08c64042fbb9de13584c86e6cee", Encoded: ""},
	}

	for _, c := range cases {
		t.Run(c.Name, func(t *testing.T) {
			pubKey, err := hex.DecodeString(c.PubKey)

			if err != nil {
				t.Fail()
				return
			}

			encoded := tezos.EncodePubKey(c.PubkeyHash, pubKey)

			if encoded != c.Encoded {
				fmt.Printf("%s: Expected %v but got %v\n", c.Name, c.Encoded, encoded)
				t.Fail()
			}
		})
	}
}
