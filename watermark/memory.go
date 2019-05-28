package watermark

import (
	"math/big"
	"sync"
)

// Memory keep previous operation in memory
type Memory struct {
	watermarks map[string]*big.Int
	mtx        *sync.Mutex
}

// NewMemory create a new Memory watermark
func NewMemory() *Memory {
	return &Memory{
		watermarks: make(map[string]*big.Int),
		mtx:        &sync.Mutex{},
	}
}

// IsSafeToSign return true if this msgID is safe to sign
func (w *Memory) IsSafeToSign(msgID string, level *big.Int) bool {
	if level == nil {
		return false
	}

	w.mtx.Lock()
	defer w.mtx.Unlock()

	if val, ok := w.watermarks[msgID]; ok {
		// If new level is bigger than past level allow signing
		if level.Cmp(val) > 0 {
			w.watermarks[msgID] = level
			return true
		}
		return false
	}

	w.watermarks[msgID] = level
	return true
}
