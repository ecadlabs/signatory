package signatory

import (
	"testing"

	"github.com/ecadlabs/signatory/pkg/tezos"
	"github.com/stretchr/testify/assert"
)

type mockMsgKind struct{}

func (m *mockMsgKind) MessageKind() string { return "foo" }

type mockMsgID struct {
	mockMsgKind
	level   int32
	chainID string
}

func (m *mockMsgID) GetChainID() string { return m.chainID }

func (m *mockMsgID) GetLevel() int32 { return m.level }

func TestGetSigAlg(t *testing.T) {
	type testCase struct {
		Name     string
		data     []tezos.UnsignedMessage
		expected bool
	}

	cases := []testCase{
		{
			Name: "Standard",
			data: []tezos.UnsignedMessage{
				&mockMsgID{level: 1, chainID: "123"},
			},
			expected: true,
		},
		{
			Name: "Standard different message ID",
			data: []tezos.UnsignedMessage{
				&mockMsgID{level: 1, chainID: "123"},
				&mockMsgID{level: 1, chainID: "124"},
			},
			expected: true,
		},
		{
			Name: "Standard Multiple",
			data: []tezos.UnsignedMessage{
				&mockMsgID{level: 1, chainID: "123"},
				&mockMsgID{level: 2, chainID: "123"},
			},
			expected: true,
		},
		{
			Name: "Not allowed negative level",
			data: []tezos.UnsignedMessage{
				&mockMsgID{level: 1, chainID: "123"},
				&mockMsgID{level: 0, chainID: "123"},
			},
			expected: false,
		},
		{
			Name: "Not allowed",
			data: []tezos.UnsignedMessage{
				&mockMsgID{level: 1, chainID: "123"},
				&mockMsgID{level: 1, chainID: "123"},
			},
			expected: false,
		},
		{
			Name: "Not required",
			data: []tezos.UnsignedMessage{
				&mockMsgKind{},
			},
			expected: true,
		},
	}

	for _, c := range cases {
		t.Run(c.Name, func(t *testing.T) {
			m := NewInMemoryWatermark()
			var res bool
			for _, d := range c.data {
				res = m.IsSafeToSign("bar", d)
			}

			assert.Equal(t, c.expected, res)
		})
	}
}
