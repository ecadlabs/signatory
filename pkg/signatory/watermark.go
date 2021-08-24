package signatory

import (
	"fmt"
	"sync"

	"github.com/ecadlabs/signatory/pkg/tezos"
)

// Watermark tests level against stored high watermark
type Watermark interface {
	IsSafeToSign(pkh string, msg tezos.UnsignedMessage) error
}

// InMemoryWatermark keep previous operation in memory
type InMemoryWatermark struct {
	watermarks map[string]int32
	mtx        sync.Mutex
}

// IsSafeToSign return true if this msgID is safe to sign
func (w *InMemoryWatermark) IsSafeToSign(pkh string, msg tezos.UnsignedMessage) error {
	msgWithChainID, ok := msg.(tezos.MessageWithLevelAndChainID)
	if !ok {
		// watermark is not required
		return nil
	}

	msgID := fmt.Sprintf("%s:%s:%s", pkh, msgWithChainID.GetChainID(), msg.MessageKind())
	level := msgWithChainID.GetLevel()

	w.mtx.Lock()
	defer w.mtx.Unlock()

	if val, ok := w.watermarks[msgID]; ok {
		// If new level is bigger than past level allow signing
		if level > val {
			w.watermarks[msgID] = level
			return nil
		}
		return fmt.Errorf("requested level %d is at or below watermark %d", level, val)
	}

	if w.watermarks == nil {
		w.watermarks = make(map[string]int32)
	}
	w.watermarks[msgID] = level
	return nil
}

// IgnoreWatermark watermark that do not validation and return true
type IgnoreWatermark struct {
}

// IsSafeToSign always return true
func (w IgnoreWatermark) IsSafeToSign(pkh string, msg tezos.UnsignedMessage) error {
	return nil
}

var (
	_ Watermark = (*InMemoryWatermark)(nil)
	_ Watermark = (*IgnoreWatermark)(nil)
)
