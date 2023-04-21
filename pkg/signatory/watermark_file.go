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

/*
func (f *FileWatermark) tryLegacy(wm *request.Watermark) (delegateMap, error) {
	dir := filepath.Join(f.BaseDir, legacyWatermarkDir)
	filename := filepath.Join(dir, fmt.Sprintf("%s.json", wm.Chain.String()))

}
*/

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
