package watermark

import (
	"context"
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
	"github.com/ecadlabs/gotez/v2/protocol/core"
	"github.com/ecadlabs/signatory/pkg/config"
	"github.com/ecadlabs/signatory/pkg/hashmap"
	"github.com/ecadlabs/signatory/pkg/metrics"
	"github.com/ecadlabs/signatory/pkg/signatory/request"
	"github.com/ecadlabs/signatory/pkg/utils"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
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
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil // Not an error, just no data
		}
		return nil, err
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
		var delegates delegateMap
		decodeErr := json.NewDecoder(fd).Decode(&delegates)
		if closeErr := fd.Close(); closeErr != nil && decodeErr == nil {
			return nil, closeErr
		}
		if decodeErr != nil {
			return nil, decodeErr
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
	opts := metrics.IOInterceptorOptions[map[tz.ChainID]delegateMap]{
		Backend:   "file",
		Operation: "read",
		TableName: "",
		TargetFunc: func() (map[tz.ChainID]delegateMap, error) {
			return tryLoad(baseDir)
		},
	}
	wm.mem.chains, err = metrics.IOInterceptor(&opts)
	if err != nil {
		return nil, err
	}

	if wm.mem.chains != nil {
		// load ok, give a warning if legacy data still exist
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

func write(baseDir string, data delegateMap, chain *tz.ChainID) error {
	dir := filepath.Join(baseDir, watermarkDir)
	if err := os.MkdirAll(dir, 0750); err != nil {
		return err
	}

	buf, err := json.MarshalIndent(data, "", "    ")
	if err != nil {
		return err
	}

	path := filepath.Join(dir, fmt.Sprintf("%s.json", chain.String()))
	return utils.WriteRename(path, "watermark", buf)
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
	opts := metrics.IOInterceptorOptions[bool]{
		Backend:   "file",
		Operation: "write",
		TableName: "",
		TargetFunc: func() (bool, error) {
			err := write(baseDir, data, chain)
			return err == nil, err
		},
	}
	_, err := metrics.IOInterceptor(&opts)
	return err
}

func (f *File) IsSafeToSign(ctx context.Context, pkh crypt.PublicKeyHash, req core.SignRequest, digest *crypt.Digest) error {
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

func init() {
	RegisterWatermark("file", func(ctx context.Context, node *yaml.Node, global config.GlobalContext) (watermarkImpl, error) {
		return NewFileWatermark(global.GetBaseDir())
	})
}
