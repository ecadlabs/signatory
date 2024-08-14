package watermark

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	tz "github.com/ecadlabs/gotez/v2"
	"github.com/ecadlabs/gotez/v2/b58"
	"github.com/ecadlabs/signatory/pkg/hashmap"
	"github.com/ecadlabs/signatory/pkg/signatory/request"
)

type v0KindMap map[string]v0WatermarkMap
type v0WatermarkMap = hashmap.PublicKeyHashMap[*request.Watermark]

const v0WatermarkDir = "watermark"

func checkV0exist(baseDir string) (bool, error) {
	filename := filepath.Join(baseDir, v0WatermarkDir)
	_, err := os.Stat(filename)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			return false, err
		}
		return false, nil
	}
	return true, nil
}

func tryV0(baseDir string) (map[tz.ChainID]delegateMap, error) {
	dir := filepath.Join(baseDir, v0WatermarkDir)
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
		var kinds v0KindMap
		if err = json.NewDecoder(fd).Decode(&kinds); err != nil {
			return nil, err
		}

		outDelegates := make(delegateMap)
		for kind, delegates := range kinds {
			delegates.ForEach(func(key tz.PublicKeyHash, val *request.Watermark) bool {
				kinds, ok := outDelegates.Get(key)
				if !ok {
					kinds = make(requestMap)
					outDelegates.Insert(key, kinds)
				}
				kinds[kind] = val
				return true
			})
		}
		out[*chainID] = outDelegates
	}

	return out, nil
}

type v1Watermark struct {
	Level int32                          `json:"level"`
	Round tz.Option[int32]               `json:"round"`
	Order int                            `json:"order"`
	Hash  tz.Option[tz.BlockPayloadHash] `json:"hash"`
}

type v1DelegateMap = hashmap.PublicKeyHashMap[*v1Watermark]

const v1WatermarkDir = "watermark_v1"

func checkV1exist(baseDir string) (bool, error) {
	filename := filepath.Join(baseDir, v1WatermarkDir)
	_, err := os.Stat(filename)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			return false, err
		}
		return false, nil
	}
	return true, nil
}

func tryV1(baseDir string) (map[tz.ChainID]delegateMap, error) {
	dir := filepath.Join(baseDir, v1WatermarkDir)
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
		var delegates v1DelegateMap
		if err = json.NewDecoder(fd).Decode(&delegates); err != nil {
			return nil, err
		}

		outDelegates := make(delegateMap)
		delegates.ForEach(func(key tz.PublicKeyHash, val *v1Watermark) bool {
			var req string
			switch val.Order {
			case 0:
				req = "block"
			case 1:
				req = "preendorsement"
			default:
				req = "endorsement"
			}

			wm := request.Watermark{
				Level: val.Level,
			}
			if val.Round.IsSome() {
				wm.Round = val.Round.Unwrap()
			}
			if val.Hash.IsSome() {
				hash := val.Hash.Unwrap()
				wm.Hash = tz.Some(hash)
			}
			outDelegates.Insert(key, map[string]*request.Watermark{
				req: &wm,
			})
			return true
		})
		out[*chainID] = outDelegates
	}

	return out, nil
}
