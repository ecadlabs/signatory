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
	log "github.com/sirupsen/logrus"
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

func (f *FileWatermark) tryLegacy(filename string) (delegateMap, error) {
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

	out := make(delegateMap)
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

func writeWatermarkData(data delegateMap, filename string) error {
	fd, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer fd.Close()
	w := bufio.NewWriter(fd)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "    ")
	if err = enc.Encode(data); err != nil {
		return err
	}
	return w.Flush()
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
	legacyFilename := filepath.Join(f.BaseDir, legacyWatermarkDir, fmt.Sprintf("%s.json", watermark.Chain.String()))

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
		if legacy, err := f.tryLegacy(legacyFilename); err != nil {
			return err
		} else if legacy != nil {
			log.Warn("Watermark storage directory %s is deprecated and must me removed manually", legacyWatermarkDir, watermarkDir)
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	} else if delegates, err = f.tryLegacy(legacyFilename); err != nil {
		return err
	} else if delegates != nil {
		// successful migration
		if err := writeWatermarkData(delegates, filename); err != nil {
			return err
		}
		log.Info("Watermark data migrated successfully to %s. Old watermark storage directory %s can now be safely removed", watermarkDir, legacyWatermarkDir)
	} else {
		delegates = make(delegateMap)
	}

	if wm, ok := delegates.Get(pkh); ok {
		if !watermark.Validate(wm, digest) {
			return ErrWatermark
		}
	}
	delegates.Insert(pkh, watermark.Stored(digest))
	return writeWatermarkData(delegates, filename)
}

var _ Watermark = (*FileWatermark)(nil)
