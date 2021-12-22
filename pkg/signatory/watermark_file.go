package signatory

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"

	"github.com/ecadlabs/signatory/pkg/tezos"
)

// chain -> kind -> delegate(pkh)
type chainMap map[string]kindMap
type kindMap map[string]watermarkMap
type watermarkMap map[string]*watermarkData

type watermarkData struct {
	Round int32  `json:"round,omitempty"`
	Level int32  `json:"level"`
	Hash  string `json:"hash,omitempty"`
}

func (w *watermarkData) isSafeToSign(msg tezos.MessageWithLevel, hash []byte) error {
	var whash []byte
	if w.Hash != "" {
		h, err := tezos.DecodeValueHash(w.Hash)
		if err != nil {
			return err
		}
		whash = h[:]
	}
	dataMatched := bytes.Equal(whash, hash)

	var round int32 = 0
	if mr, ok := msg.(tezos.MessageWithRound); ok {
		round = mr.GetRound()
	}

	switch {
	case w.Level == msg.GetLevel() && w.Round == round && !dataMatched:
		return fmt.Errorf("%s level %d and round %d already signed with different data", msg.MessageKind(), msg.GetLevel(), round)
	case w.Level > msg.GetLevel():
		return fmt.Errorf("%s level %d not above high watermark %d", msg.MessageKind(), msg.GetLevel(), w.Level)
	case w.Level == msg.GetLevel() && w.Round > round:
		return fmt.Errorf("%s level %d and round %d not above high watermark (%d,%d)", msg.MessageKind(), msg.GetLevel(), round, w.Level, w.Round)
	}

	return nil
}

const watermarkDir = "watermark"

type FileWatermark struct {
	BaseDir string
	mtx     sync.Mutex
}

func (f *FileWatermark) IsSafeToSign(pkh string, hash []byte, msg tezos.UnsignedMessage) error {
	m, ok := msg.(tezos.MessageWithLevel)
	if !ok {
		// watermark is not required
		return nil
	}

	dir := filepath.Join(f.BaseDir, watermarkDir)
	if err := os.MkdirAll(dir, 0770); err != nil {
		return err
	}
	filename := filepath.Join(dir, fmt.Sprintf("%s.json", m.GetChainID()))

	f.mtx.Lock()
	defer f.mtx.Unlock()

	var kinds kindMap
	fd, err := os.Open(filename)
	if err == nil {
		err = json.NewDecoder(fd).Decode(&kinds)
		fd.Close()
		if err != nil {
			return err
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	} else {
		kinds = make(kindMap)
	}

	if wm, ok := kinds[m.MessageKind()]; ok {
		if wd, ok := wm[pkh]; ok {
			if err := wd.isSafeToSign(m, hash); err != nil {
				return err
			}
		}
	}

	wm, ok := kinds[m.MessageKind()]
	if !ok {
		wm = make(watermarkMap)
		kinds[m.MessageKind()] = wm
	}
	var round int32 = 0
	if mr, ok := msg.(tezos.MessageWithRound); ok {
		round = mr.GetRound()
	}
	var ench string
	if hash != nil {
		ench = tezos.EncodeValueHash(hash)
	}
	wm[pkh] = &watermarkData{
		Round: round,
		Level: m.GetLevel(),
		Hash:  ench,
	}

	fd, err = os.Create(filename)
	if err != nil {
		return err
	}
	defer fd.Close()
	enc := json.NewEncoder(fd)
	enc.SetIndent("", "    ")
	return enc.Encode(kinds)
}
