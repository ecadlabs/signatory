package signatory

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"

	"github.com/ecadlabs/signatory/pkg/signatory/request"
)

// chain -> delegate(pkh)
type chainMap map[string]watermarkMap
type watermarkMap map[string]*request.StoredWatermark

var ErrWatermark = errors.New("watermark validation failed")

const watermarkDir = "watermark_v1"

type FileWatermark struct {
	BaseDir string
	mtx     sync.Mutex
}

func (f *FileWatermark) IsSafeToSign(pkh string, req request.SignRequest) error {
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

	var chains chainMap
	fd, err := os.Open(filename)
	if err == nil {
		err = json.NewDecoder(fd).Decode(&chains)
		fd.Close()
		if err != nil {
			return err
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	} else {
		chains = make(chainMap)
	}

	delegates, ok := chains[watermark.Chain.String()]
	if ok {
		if wm, ok := delegates[pkh]; ok {
			if !watermark.Validate(wm) {
				return ErrWatermark
			}
		}
	} else {
		delegates = make(watermarkMap)
		chains[watermark.Chain.String()] = delegates
	}
	delegates[pkh] = watermark.Stored()

	fd, err = os.Create(filename)
	if err != nil {
		return err
	}
	defer fd.Close()
	enc := json.NewEncoder(fd)
	enc.SetIndent("", "    ")
	return enc.Encode(chains)
}

var _ Watermark = (*FileWatermark)(nil)
