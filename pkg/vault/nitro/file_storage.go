package nitro

import (
	"bufio"
	"context"
	"encoding/json"
	"iter"
	"os"
	"slices"
	"sync"
)

type fileStorage struct {
	path string
	mtx  sync.RWMutex
	keys [][]byte
}

func newFileStorage(path string) (*fileStorage, error) {
	fd, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer fd.Close()
	var keys [][]byte
	if err = json.NewDecoder(fd).Decode(&keys); err != nil {
		return nil, err
	}
	return &fileStorage{
		path: path,
		keys: keys,
	}, nil
}

type fileResult struct {
	keys [][]byte
}

func (f *fileResult) Err() error { return nil }
func (f *fileResult) Result() iter.Seq[[]byte] {
	return slices.Values(f.keys)
}

func (f *fileStorage) GetKeys(ctx context.Context) (Result[[]byte], error) {
	f.mtx.RLock()
	defer f.mtx.RUnlock()

	return &fileResult{keys: f.keys}, nil
}

func (f *fileStorage) ImportKey(ctx context.Context, encryptedKeyData []byte) error {
	f.mtx.Lock()
	defer f.mtx.Unlock()

	f.keys = append(f.keys, encryptedKeyData)

	fd, err := os.Create(f.path)
	if err != nil {
		return err
	}
	w := bufio.NewWriter(fd)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "    ")
	if err = enc.Encode(f.keys); err != nil {
		return err
	}
	return w.Flush()
}
