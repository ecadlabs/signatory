package request

import (
	"testing"

	tz "github.com/ecadlabs/gotez"
	"github.com/stretchr/testify/require"
)

func TestWatermark(t *testing.T) {
	type expect struct {
		wm     Watermark
		expect bool
	}

	type testCase struct {
		stored StoredWatermark
		expect []expect
	}

	testCases := []testCase{
		{
			stored: StoredWatermark{
				Level: Level{
					Level: 1,
					Round: tz.Some(int32(1)),
				},
				Order: WmOrderDefault,
			},
			expect: []expect{
				{
					wm: Watermark{
						Chain: &tz.ChainID{},
						Level: Level{
							Level: 2,
							Round: tz.Some(int32(0)),
						},
						Order: WmOrderDefault,
					},
					expect: true, // level above
				},
				{
					wm: Watermark{
						Chain: &tz.ChainID{},
						Level: Level{
							Level: 2,
							Round: tz.None[int32](),
						},
						Order: WmOrderDefault,
					},
					expect: false, // round is set above
				},
				{
					wm: Watermark{
						Chain: &tz.ChainID{},
						Level: Level{
							Level: 2,
							Round: tz.Some(int32(2)),
						},
						Order: WmOrderDefault,
					},
					expect: true, // level and round above
				},
				{
					wm: Watermark{
						Chain: &tz.ChainID{},
						Level: Level{
							Level: 1,
							Round: tz.Some(int32(2)),
						},
						Order: WmOrderDefault,
					},
					expect: true, // round above
				},
				{
					wm: Watermark{
						Chain: &tz.ChainID{},
						Level: Level{
							Level: 0,
							Round: tz.Some(int32(2)),
						},
						Order: WmOrderDefault,
					},
					expect: false, // level below
				},
				{
					wm: Watermark{
						Chain: &tz.ChainID{},
						Level: Level{
							Level: 1,
							Round: tz.Some(int32(1)),
						},
						Order: WmOrderDefault,
					},
					expect: false, // level and round below
				},
				{
					wm: Watermark{
						Chain: &tz.ChainID{},
						Level: Level{
							Level: 1,
							Round: tz.Some(int32(1)),
						},
						Order: WmOrderEndorsement,
					},
					expect: true, // don't have endorsement
				},
			},
		},
		{
			stored: StoredWatermark{
				Level: Level{
					Level: 1,
					Round: tz.Some(int32(1)),
				},
				Order: WmOrderEndorsement,
			},
			expect: []expect{
				{
					wm: Watermark{
						Chain: &tz.ChainID{},
						Level: Level{
							Level: 2,
							Round: tz.Some(int32(0)),
						},
						Order: WmOrderDefault,
					},
					expect: true, // level above
				},
				{
					wm: Watermark{
						Chain: &tz.ChainID{},
						Level: Level{
							Level: 2,
							Round: tz.Some(int32(0)),
						},
						Order: WmOrderEndorsement,
					},
					expect: true, // level above
				},
				{
					wm: Watermark{
						Chain: &tz.ChainID{},
						Level: Level{
							Level: 2,
							Round: tz.Some(int32(2)),
						},
						Order: WmOrderDefault,
					},
					expect: true, // level and round above
				},
				{
					wm: Watermark{
						Chain: &tz.ChainID{},
						Level: Level{
							Level: 2,
							Round: tz.Some(int32(2)),
						},
						Order: WmOrderEndorsement,
					},
					expect: true, // level and round above
				},
				{
					wm: Watermark{
						Chain: &tz.ChainID{},
						Level: Level{
							Level: 1,
							Round: tz.Some(int32(2)),
						},
						Order: WmOrderDefault,
					},
					expect: true, // round above
				},
				{
					wm: Watermark{
						Chain: &tz.ChainID{},
						Level: Level{
							Level: 1,
							Round: tz.Some(int32(2)),
						},
						Order: WmOrderEndorsement,
					},
					expect: true, // order above
				},
				{
					wm: Watermark{
						Chain: &tz.ChainID{},
						Level: Level{
							Level: 0,
							Round: tz.Some(int32(2)),
						},
						Order: WmOrderDefault,
					},
					expect: false, // level below
				},
				{
					wm: Watermark{
						Chain: &tz.ChainID{},
						Level: Level{
							Level: 0,
							Round: tz.Some(int32(2)),
						},
						Order: WmOrderEndorsement,
					},
					expect: false, // level below
				},
				{
					wm: Watermark{
						Chain: &tz.ChainID{},
						Level: Level{
							Level: 1,
							Round: tz.Some(int32(1)),
						},
						Order: WmOrderDefault,
					},
					expect: false, // level and round below
				},
				{
					wm: Watermark{
						Chain: &tz.ChainID{},
						Level: Level{
							Level: 1,
							Round: tz.Some(int32(1)),
						},
						Order: WmOrderEndorsement,
					},
					expect: false, // have endorsement
				},
			},
		},
		{
			stored: StoredWatermark{
				Level: Level{
					Level: 1,
					Round: tz.None[int32](),
				},
				Order: WmOrderDefault,
			},
			expect: []expect{
				{
					wm: Watermark{
						Chain: &tz.ChainID{},
						Level: Level{
							Level: 2,
							Round: tz.None[int32](),
						},
						Order: WmOrderDefault,
					},
					expect: true, // level above
				},
				{
					wm: Watermark{
						Chain: &tz.ChainID{},
						Level: Level{
							Level: 2,
							Round: tz.Some(int32(2)),
						},
						Order: WmOrderDefault,
					},
					expect: true, // level above
				},
				{
					wm: Watermark{
						Chain: &tz.ChainID{},
						Level: Level{
							Level: 0,
							Round: tz.None[int32](),
						},
						Order: WmOrderDefault,
					},
					expect: false, // level below
				},
			},
		},
	}

	for _, c := range testCases {
		for _, ex := range c.expect {
			require.Equal(t, ex.expect, ex.wm.Validate(&c.stored))
		}
	}
}
