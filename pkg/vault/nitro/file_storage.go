package nitro

import (
	"context"
	"encoding/json"
	"errors"
	"iter"
	"os"
	"slices"
	"sync"

	"github.com/ecadlabs/signatory/pkg/utils"
)

type fileStorage struct {
	path string
	mtx  sync.RWMutex
	keys []*encryptedKey
}

func newFileStorage(path string) (*fileStorage, error) {
	fd, err := os.Open(path)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		} else {
			return &fileStorage{
				path: path,
				keys: make([]*encryptedKey, 0),
			}, nil
		}
	}
	defer fd.Close()
	var keys []*encryptedKey
	if err = json.NewDecoder(fd).Decode(&keys); err != nil {
		return nil, err
	}
	return &fileStorage{
		path: path,
		keys: keys,
	}, nil
}

type fileResult struct {
	keys []*encryptedKey
}

func (f *fileResult) Err() error { return nil }
func (f *fileResult) Result() iter.Seq[*encryptedKey] {
	return slices.Values(f.keys)
}

func (f *fileStorage) GetKeys(ctx context.Context) (result[*encryptedKey], error) {
	f.mtx.RLock()
	defer f.mtx.RUnlock()
	return &fileResult{keys: f.keys}, nil
}

func (f *fileStorage) ImportKey(ctx context.Context, encryptedKey *encryptedKey) (err error) {
	f.mtx.Lock()
	defer f.mtx.Unlock()

	f.keys = append(f.keys, encryptedKey)

	data, err := json.MarshalIndent(f.keys, "", "    ")
	if err != nil {
		return err
	}
	return utils.WriteRename(f.path, "keys", data)
}
