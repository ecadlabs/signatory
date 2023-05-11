package signatory

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"

	tz "github.com/ecadlabs/gotez"
	"github.com/ecadlabs/signatory/pkg/crypt"
	"github.com/ecadlabs/signatory/pkg/hashmap"
	"github.com/ecadlabs/signatory/pkg/signatory/request"
)

// chain -> delegate(pkh)
type delegateMap = hashmap.PublicKeyHashMap[*request.StoredWatermark]
type chainMap map[tz.ChainID]delegateMap

var ErrWatermark = errors.New("watermark validation failed")

const watermarkDir = "watermark_v1"

type FileWatermark struct {
	BaseDir string
	mtx     sync.Mutex
}

type legacyWatermarkData struct {
	Round int32                          `json:"round,omitempty"`
	Level int32                          `json:"level"`
	Hash  tz.Option[tz.BlockPayloadHash] `json:"hash"`
}

type legacyKindMap map[string]legacyWatermarkMap
type legacyWatermarkMap = hashmap.PublicKeyHashMap[*legacyWatermarkData]

const legacyWatermarkDir = "watermark"

func (f *FileWatermark) tryLegacy(wm *request.Watermark) (delegateMap, error) {
	out := make(delegateMap)
	dir := filepath.Join(f.BaseDir, legacyWatermarkDir)
	filename := filepath.Join(dir, fmt.Sprintf("%s.json", wm.Chain.String()))

	var kinds legacyKindMap
	fd, err := os.Open(filename)
	if err == nil {
		err = json.NewDecoder(fd).Decode(&kinds)
		fd.Close()
		if err != nil {
			return nil, err
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	} else {
		return nil, nil
	}

	orders := []struct {
		kind  string
		order int
	}{
		{"endorsement", request.WmOrderEndorsement},
		{"preendorsement", request.WmOrderPreendorsement},
		{"block", request.WmOrderDefault},
		{"generic", request.WmOrderDefault},
	}

	for _, o := range orders {
		if wm, ok := kinds[o.kind]; ok {
			wm.ForEach(func(pkh tz.PublicKeyHash, data *legacyWatermarkData) bool {
				stored := request.StoredWatermark{
					Level: request.Level{
						Level: data.Level,
						Round: tz.Some(data.Round),
					},
					Order: o.order,
					Hash:  data.Hash,
				}
				if s, ok := out.Get(pkh); !ok || ok && s.Order <= o.order {
					out.Insert(pkh, &stored)
				}
				return true
			})
		}
	}

	return out, nil
}

func (f *FileWatermark) IsSafeToSign(pkh crypt.PublicKeyHash, req request.SignRequest, digest *crypt.Digest) error {
	m, ok := req.(request.WithWatermark)
	if !ok {
		// watermark is not required
		return nil
	}
	watermark := m.Watermark()

	dir := filepath.Join(f.BaseDir, watermarkDir)
	if err := os.MkdirAll(dir, 0770); err != nil {
		return err
	}
	filename := filepath.Join(dir, fmt.Sprintf("%s.json", watermark.Chain.String()))

	f.mtx.Lock()
	defer f.mtx.Unlock()

	var delegates delegateMap
	fd, err := os.Open(filename)
	if err == nil {
		err = json.NewDecoder(fd).Decode(&delegates)
		fd.Close()
		if err != nil {
			return err
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	} else if delegates, err = f.tryLegacy(watermark); err != nil {
		return err
	} else if delegates != nil {
		// successful migration
		fd, err = os.Create(filename)
		if err != nil {
			return err
		}
		enc := json.NewEncoder(fd)
		enc.SetIndent("", "    ")
		if err := enc.Encode(delegates); err != nil {
			return err
		}
		if err := fd.Close(); err != nil {
			return err
		}
	} else {
		delegates = make(delegateMap)
	}

	if wm, ok := delegates.Get(pkh); ok {
		if !watermark.Validate(wm, digest) {
			return ErrWatermark
		}
	}
	delegates.Insert(pkh, watermark.Stored(digest))

	fd, err = os.Create(filename)
	if err != nil {
		return err
	}
	defer fd.Close()
	w := bufio.NewWriter(fd)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "    ")
	if err := enc.Encode(delegates); err != nil {
		return err
	}
	return w.Flush()
}

var _ Watermark = (*FileWatermark)(nil)
