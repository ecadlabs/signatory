//go:build !integration

package request

import (
	"testing"

	tz "github.com/ecadlabs/gotez"
	"github.com/ecadlabs/signatory/pkg/crypt"
	"github.com/stretchr/testify/require"
)

type dummyMsg struct {
	level int32
	round int32
}

func (r *dummyMsg) RequestKind() string     { return "dummy" }
func (r *dummyMsg) GetChainID() *tz.ChainID { return &tz.ChainID{} }
func (r *dummyMsg) GetLevel() int32         { return r.level }
func (r *dummyMsg) GetRound() int32         { return r.round }

func TestWatermark(t *testing.T) {
	type expect struct {
		req    WithWatermark
		digest *crypt.Digest
		expect bool
	}

	type testCase struct {
		stored Watermark
		expect []expect
	}

	testCases := []testCase{
		{
			stored: Watermark{
				Level: 1,
				Round: 1,
			},
			expect: []expect{
				{
					req: &dummyMsg{
						level: 2,
						round: 0,
					},
					digest: &crypt.Digest{0},
					expect: true, // level above
				},
				{
					req: &dummyMsg{
						level: 1,
						round: 2,
					},
					digest: &crypt.Digest{0},
					expect: true, // round above
				},
				{
					req: &dummyMsg{
						level: 1,
						round: 1,
					},
					digest: &crypt.Digest{0},
					expect: false, // repeated
				},
				{
					req: &dummyMsg{
						level: 1,
						round: 0,
					},
					digest: &crypt.Digest{0},
					expect: false, // round below
				},
				{
					req: &dummyMsg{
						level: 0,
						round: 2,
					},
					digest: &crypt.Digest{0},
					expect: false, // level below
				},
			},
		},
		{
			stored: Watermark{
				Level: 1,
				Round: 1,
				Hash:  tz.Some(tz.BlockPayloadHash{0}),
			},
			expect: []expect{
				{
					req: &dummyMsg{
						level: 2,
						round: 0,
					},
					digest: &crypt.Digest{1},
					expect: true, // level above
				},
				{
					req: &dummyMsg{
						level: 1,
						round: 2,
					},
					digest: &crypt.Digest{1},
					expect: true, // round above
				},
				{
					req: &dummyMsg{
						level: 1,
						round: 1,
					},
					digest: &crypt.Digest{0},
					expect: true, // hash match
				},
				{
					req: &dummyMsg{
						level: 1,
						round: 0,
					},
					digest: &crypt.Digest{1},
					expect: false, // round below
				},
				{
					req: &dummyMsg{
						level: 0,
						round: 2,
					},
					digest: &crypt.Digest{1},
					expect: false, // level below
				},
				{
					req: &dummyMsg{
						level: 1,
						round: 1,
					},
					digest: &crypt.Digest{1},
					expect: false, // repeated
				},
			},
		},
	}

	for _, c := range testCases {
		for _, ex := range c.expect {
			wm := NewWatermark(ex.req, ex.digest)
			require.Equal(t, ex.expect, wm.Validate(&c.stored))
		}
	}
}
