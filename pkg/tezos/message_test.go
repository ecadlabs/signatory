package tezos_test

import (
	"fmt"
	"testing"

	"github.com/ecadlabs/signatory/pkg/config"
	"github.com/ecadlabs/signatory/pkg/tezos"
	"github.com/stretchr/testify/require"
)

func TestValidateMessage(t *testing.T) {
	type Case struct {
		Name    string
		Message []byte
		Error   error
	}

	cases := []Case{
		Case{Name: "Nil message", Message: nil, Error: &tezos.MessageTooShortError{Len: 0}},
		Case{Name: "Empty message", Message: []byte{}, Error: &tezos.MessageTooShortError{Len: 0}},
		Case{Name: "Generic operation", Message: []byte{0x03, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05}, Error: nil},
		Case{Name: "Endorsement operation", Message: []byte{0x02, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06}, Error: nil},
		Case{Name: "Block operation", Message: []byte{0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07}, Error: nil},
		Case{Name: "Invalid magic byte", Message: []byte{0x00, 0x02}, Error: &tezos.MagicByteError{Value: 0}},
		Case{Name: "Invalid magic byte", Message: []byte{0x04, 0x02}, Error: &tezos.MagicByteError{Value: 4}},
	}

	for _, c := range cases {
		t.Run(c.Name, func(t *testing.T) {
			msg := tezos.ParseMessage(c.Message)
			err := msg.Validate()
			require.Equal(t, c.Error, err)
		})
	}
}

func TestGetMessageType(t *testing.T) {
	type Case struct {
		Name    string
		Message []byte
		Type    string
	}

	cases := []Case{
		Case{Name: "Generic operation", Message: []byte{0x03, 0x02}, Type: tezos.OpGeneric},
		Case{Name: "Endorsement operation", Message: []byte{0x02, 0x02}, Type: tezos.OpEndorsement},
		Case{Name: "Block operation", Message: []byte{0x01, 0x02}, Type: tezos.OpBlock},
		Case{Name: "Unknown operation", Message: []byte{0x05, 0x02}, Type: tezos.OpUnknown},
	}

	for _, c := range cases {
		t.Run(c.Name, func(t *testing.T) {
			msg := tezos.ParseMessage(c.Message)
			msgType := msg.Type()

			if msgType != c.Type {
				fmt.Printf("Expected %v but got %v\n", c.Type, msgType)
				t.Fail()
			}
		})
	}
}

func TestFilterMessage(t *testing.T) {
	type Case struct {
		Name    string
		Message []byte
		Config  *config.TezosPolicy
		Error   error
	}

	genTezosConfig := func(filters []string, kinds []string) *config.TezosPolicy {
		return &config.TezosPolicy{
			AllowedOperations: filters,
			AllowedKinds:      kinds,
		}
	}

	createGeneric := func(b byte) []byte {
		generic := make([]byte, 50)
		generic[0] = 0x03
		generic[33] = b
		return generic
	}

	cases := []Case{
		Case{Name: "Nil message", Message: nil, Error: &tezos.FilterError{}},
		Case{Name: "Empty message", Message: []byte{}, Error: &tezos.FilterError{}},
		Case{Name: "Endorsement operation", Message: []byte{0x02, 0x02}, Error: nil, Config: genTezosConfig([]string{tezos.OpEndorsement}, nil)},
		Case{Name: "Block operation", Message: []byte{0x01, 0x02}, Error: nil, Config: genTezosConfig([]string{tezos.OpBlock}, nil)},
		Case{Name: "Invalid magic byte", Message: []byte{0x00, 0x02}, Error: &tezos.FilterError{}},
		Case{Name: "Invalid magic byte", Message: []byte{0x04, 0x02}, Error: &tezos.FilterError{}},
		Case{Name: "Unsupported operation", Message: []byte{0x03, 0x02}, Error: &tezos.FilterError{}, Config: genTezosConfig([]string{tezos.OpBlock, tezos.OpEndorsement}, nil)},
		Case{Name: "Unsupported operation", Message: []byte{0x01, 0x02}, Error: &tezos.FilterError{}, Config: genTezosConfig([]string{tezos.OpGeneric}, nil)},

		Case{Name: "Generic operation not configured", Message: []byte{0x03, 0x02}, Error: &tezos.FilterError{}, Config: genTezosConfig([]string{tezos.OpGeneric}, nil)},
		Case{Name: "Generic operation not long enough", Message: []byte{0x03, 0x02}, Error: &tezos.FilterError{}, Config: genTezosConfig([]string{tezos.OpGeneric}, []string{tezos.OpGenBallot})},
		Case{Name: "Generic operation unknown not long enough", Message: []byte{0x03, 0x02}, Error: nil, Config: genTezosConfig([]string{tezos.OpGeneric}, []string{tezos.OpGenUnknown})},
		Case{Name: "Generic operation ballot", Message: createGeneric(0x06), Error: nil, Config: genTezosConfig([]string{tezos.OpGeneric}, []string{tezos.OpGenBallot})},
		Case{Name: "Generic operation transaction", Message: createGeneric(0x08), Error: nil, Config: genTezosConfig([]string{tezos.OpGeneric}, []string{tezos.OpGenTransaction})},
		Case{Name: "Generic operation proposal", Message: createGeneric(0x05), Error: nil, Config: genTezosConfig([]string{tezos.OpGeneric}, []string{tezos.OpGenProposal})},
		Case{Name: "Generic operation not configured but kind is configured", Message: createGeneric(0x08), Error: &tezos.FilterError{}, Config: genTezosConfig([]string{}, []string{tezos.OpGenTransaction})},
	}

	for _, c := range cases {
		t.Run(c.Name, func(t *testing.T) {
			msg := tezos.ParseMessage(c.Message)
			err := msg.MatchFilter(c.Config)

			require.Equal(t, c.Error, err)
		})
	}
}
