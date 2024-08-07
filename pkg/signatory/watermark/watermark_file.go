package watermark

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	tz "github.com/ecadlabs/gotez/v2"
	"github.com/ecadlabs/gotez/v2/b58"
	"github.com/ecadlabs/gotez/v2/crypt"
	"github.com/ecadlabs/gotez/v2/protocol"
	"github.com/ecadlabs/signatory/pkg/hashmap"
	"github.com/ecadlabs/signatory/pkg/signatory/request"
	log "github.com/sirupsen/logrus"
)

type File struct {
	baseDir string
	mem     InMemory
}

// chain -> delegate(pkh) -> request type -> watermark
type delegateMap = hashmap.PublicKeyHashMap[requestMap]
type requestMap = map[string]*request.Watermark

var ErrWatermark = errors.New("watermark validation failed")

const watermarkDir = "watermark_v2"

func tryLoad(baseDir string) (map[tz.ChainID]delegateMap, error) {
	dir := filepath.Join(baseDir, watermarkDir)
	entries, err := os.ReadDir(dir)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			return nil, err
		}
		return nil, nil
	}

	out := make(map[tz.ChainID]delegateMap)
	for _, ent := range entries {
		if !ent.Type().IsRegular() || !strings.HasSuffix(ent.Name(), ".json") {
			continue
		}
		name := ent.Name()
		chainID, err := b58.ParseChainID([]byte(name[:len(name)-5]))
		if err != nil {
			return nil, err
		}

		filename := filepath.Join(dir, name)
		fd, err := os.Open(filename)
		if err != nil {
			return nil, err
		}
		defer fd.Close()
		var delegates delegateMap
		if err = json.NewDecoder(fd).Decode(&delegates); err != nil {
			return nil, err
		}
		out[*chainID] = delegates
	}

	return out, nil
}

func NewFileWatermark(baseDir string) (*File, error) {
	wm := File{
		baseDir: baseDir,
	}
	var err error
	if wm.mem.chains, err = tryLoad(baseDir); err != nil {
		return nil, err
	}
	if wm.mem.chains != nil {
		// load ok, give a warning if legasy data still exist
		if ok, err := checkV0exist(baseDir); err == nil {
			if ok {
				log.Warnf("Watermark storage directory %s is deprecated and must be removed manually", v0WatermarkDir)
			}
		} else {
			return nil, err
		}
		if ok, err := checkV1exist(baseDir); err == nil {
			if ok {
				log.Warnf("Watermark storage directory %s is deprecated and must be removed manually", v1WatermarkDir)
			}
		} else {
			return nil, err
		}
	} else {
		// do migration
		if wm.mem.chains, err = tryV1(baseDir); err != nil {
			return nil, err
		}
		if wm.mem.chains != nil {
			if err = writeAll(baseDir, wm.mem.chains); err != nil {
				return nil, err
			}
			log.Infof("Watermark data migrated successfully to %s. Old watermark storage directory %s can now be safely removed", watermarkDir, v1WatermarkDir)
		} else {
			if wm.mem.chains, err = tryV0(baseDir); err != nil {
				return nil, err
			}
			if wm.mem.chains != nil {
				if err = writeAll(baseDir, wm.mem.chains); err != nil {
					return nil, err
				}
				log.Infof("Watermark data migrated successfully to %s. Old watermark storage directory %s can now be safely removed", watermarkDir, v0WatermarkDir)
			}
		}
	}
	return &wm, nil
}

func writeAll(baseDir string, chains map[tz.ChainID]delegateMap) error {
	for chain, data := range chains {
		if err := writeWatermarkData(baseDir, data, &chain); err != nil {
			return err
		}
	}
	return nil
}

func writeWatermarkData(baseDir string, data delegateMap, chain *tz.ChainID) error {
	dir := filepath.Join(baseDir, watermarkDir)
	if err := os.MkdirAll(dir, 0770); err != nil {
		return err
	}

	fd, err := os.Create(filepath.Join(dir, fmt.Sprintf("%s.json", chain.String())))
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

func (f *File) IsSafeToSign(pkh crypt.PublicKeyHash, req protocol.SignRequest, digest *crypt.Digest) error {
	m, ok := req.(request.WithWatermark)
	if !ok {
		// watermark is not required
		return nil
	}
	f.mem.mtx.Lock()
	defer f.mem.mtx.Unlock()

	if err := f.mem.isSafeToSignUnlocked(pkh, m, digest); err != nil {
		return err
	}
	chain := m.GetChainID()
	return writeWatermarkData(f.baseDir, f.mem.chains[*chain], chain)
}

var _ Watermark = (*File)(nil)
