package signatory

import (
	"os"
	"testing"

	"github.com/ecadlabs/signatory/pkg/tezos"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type msgMock struct {
	chainID string
	kind    string
	level   int32
	round   int32
}

func (m *msgMock) GetChainID() string  { return m.chainID }
func (m *msgMock) MessageKind() string { return m.kind }
func (m *msgMock) GetLevel() int32     { return m.level }
func (m *msgMock) GetRound() int32     { return m.round }

func TestWatermarkData(t *testing.T) {
	hash := [32]byte{1, 2, 3, 4}
	wd := watermarkData{
		Level: 123,
		Round: 1,
		Hash:  tezos.EncodeValueHash(hash[:]),
	}

	assert.NoError(t, wd.isSafeToSign(&msgMock{"dummy", "dummy", 124, 0}, nil))
	assert.NoError(t, wd.isSafeToSign(&msgMock{"dummy", "dummy", 123, 1}, hash[:]))
	assert.NoError(t, wd.isSafeToSign(&msgMock{"dummy", "dummy", 123, 2}, nil))
	assert.EqualError(t, wd.isSafeToSign(&msgMock{"dummy", "dummy", 123, 1}, nil), "dummy level 123 and round 1 already signed with different data")
	assert.EqualError(t, wd.isSafeToSign(&msgMock{"dummy", "dummy", 123, 0}, nil), "dummy level 123 and round 0 not above high watermark (123,1)")
	assert.EqualError(t, wd.isSafeToSign(&msgMock{"dummy", "dummy", 122, 0}, nil), "dummy level 122 not above high watermark 123")
}

func TestWatermarkMem(t *testing.T) {
	hash := [32]byte{1, 2, 3, 4}
	var wm InMemoryWatermark

	assert.NoError(t, wm.IsSafeToSign("pkh1", hash[:], &msgMock{"chain1", "kind1", 124, 0}))
	assert.EqualError(t, wm.IsSafeToSign("pkh1", nil, &msgMock{"chain1", "kind1", 123, 0}), "kind1 level 123 not above high watermark 124")
	assert.EqualError(t, wm.IsSafeToSign("pkh1", nil, &msgMock{"chain1", "kind1", 124, 0}), "kind1 level 124 and round 0 already signed with different data")
	assert.NoError(t, wm.IsSafeToSign("pkh1", nil, &msgMock{"chain1", "kind2", 124, 0}))
	assert.NoError(t, wm.IsSafeToSign("pkh1", nil, &msgMock{"chain1", "kind2", 124, 0}))
	assert.NoError(t, wm.IsSafeToSign("pkh2", nil, &msgMock{"chain1", "kind1", 124, 0}))
	assert.NoError(t, wm.IsSafeToSign("pkh1", hash[:], &msgMock{"chain1", "kind1", 125, 0}))
}

func TestWatermarkFile(t *testing.T) {
	dir, err := os.MkdirTemp("", "watermark")
	require.NoError(t, err)

	hash := [32]byte{1, 2, 3, 4}
	wm := FileWatermark{BaseDir: dir}

	assert.NoError(t, wm.IsSafeToSign("pkh1", hash[:], &msgMock{"chain1", "kind1", 124, 0}))
	assert.EqualError(t, wm.IsSafeToSign("pkh1", nil, &msgMock{"chain1", "kind1", 123, 0}), "kind1 level 123 not above high watermark 124")
	assert.EqualError(t, wm.IsSafeToSign("pkh1", nil, &msgMock{"chain1", "kind1", 124, 0}), "kind1 level 124 and round 0 already signed with different data")
	assert.NoError(t, wm.IsSafeToSign("pkh1", nil, &msgMock{"chain1", "kind2", 124, 0}))
	assert.NoError(t, wm.IsSafeToSign("pkh1", nil, &msgMock{"chain1", "kind2", 124, 0}))
	assert.NoError(t, wm.IsSafeToSign("pkh2", nil, &msgMock{"chain1", "kind1", 124, 0}))
	assert.NoError(t, wm.IsSafeToSign("pkh1", hash[:], &msgMock{"chain1", "kind1", 125, 0}))
}
