//go:build !integration

package signatory

import (
	"os"
	"testing"

	tz "github.com/ecadlabs/gotez"
	"github.com/ecadlabs/signatory/pkg/crypt"
	"github.com/ecadlabs/signatory/pkg/signatory/request"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type msgMock request.Watermark

func (m *msgMock) Watermark() *request.Watermark {
	return (*request.Watermark)(m)
}

func (m *msgMock) RequestKind() string { return "dummy" }

type testCase struct {
	pkh       crypt.PublicKeyHash
	req       request.SignRequest
	reqDigest crypt.Digest
	expectErr bool
}

func TestWatermark(t *testing.T) {
	cases := []testCase{
		{
			pkh: &tz.Ed25519PublicKeyHash{0},
			req: (*msgMock)(&request.Watermark{
				Chain: &tz.ChainID{},
				Level: request.Level{Level: 124},
			}),
			reqDigest: crypt.Digest{0},
			expectErr: false,
		},
		{
			pkh: &tz.Ed25519PublicKeyHash{0},
			req: (*msgMock)(&request.Watermark{
				Chain: &tz.ChainID{},
				Level: request.Level{Level: 123},
			}),
			reqDigest: crypt.Digest{1},
			expectErr: true,
		},
		{
			// repeated request
			pkh: &tz.Ed25519PublicKeyHash{0},
			req: (*msgMock)(&request.Watermark{
				Chain: &tz.ChainID{},
				Level: request.Level{Level: 124},
			}),
			reqDigest: crypt.Digest{0},
			expectErr: false,
		},
		{
			pkh: &tz.Ed25519PublicKeyHash{1},
			req: (*msgMock)(&request.Watermark{
				Chain: &tz.ChainID{},
				Level: request.Level{Level: 124},
			}),
			reqDigest: crypt.Digest{3},
			expectErr: false,
		},
		{
			pkh: &tz.Ed25519PublicKeyHash{0},
			req: (*msgMock)(&request.Watermark{
				Chain: &tz.ChainID{},
				Level: request.Level{Level: 125},
			}),
			reqDigest: crypt.Digest{4},
			expectErr: false,
		},
	}

	t.Run("memory", func(t *testing.T) {
		var wm InMemoryWatermark
		for _, c := range cases {
			err := wm.IsSafeToSign(c.pkh, c.req, &c.reqDigest)
			if c.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		}
	})

	t.Run("file", func(t *testing.T) {
		dir, err := os.MkdirTemp("", "watermark")
		require.NoError(t, err)
		wm := FileWatermark{BaseDir: dir}
		for _, c := range cases {
			err := wm.IsSafeToSign(c.pkh, c.req, &c.reqDigest)
			if c.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		}
	})
}
