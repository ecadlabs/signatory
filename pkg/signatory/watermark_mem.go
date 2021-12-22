package signatory

import (
	"sync"

	"github.com/ecadlabs/signatory/pkg/tezos"
)

// InMemoryWatermark keep previous operation in memory
type InMemoryWatermark struct {
	dir chainMap
	mtx sync.Mutex
}

// IsSafeToSign return true if this msgID is safe to sign
func (w *InMemoryWatermark) IsSafeToSign(pkh string, hash []byte, msg tezos.UnsignedMessage) error {
	m, ok := msg.(tezos.MessageWithLevel)
	if !ok {
		// watermark is not required
		return nil
	}

	w.mtx.Lock()
	defer w.mtx.Unlock()

	if kinds, ok := w.dir[m.GetChainID()]; ok {
		if wm, ok := kinds[m.MessageKind()]; ok {
			if wd, ok := wm[pkh]; ok {
				if err := wd.isSafeToSign(m, hash); err != nil {
					return err
				}
			}
		}
	}

	if w.dir == nil {
		w.dir = make(chainMap)
	}
	kinds, ok := w.dir[m.GetChainID()]
	if !ok {
		kinds = make(kindMap)
		w.dir[m.GetChainID()] = kinds
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

	return nil
}

var _ Watermark = (*InMemoryWatermark)(nil)
