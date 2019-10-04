package signatory

import (
	"fmt"
	"sync"

	"github.com/ecadlabs/signatory/pkg/tezos"
)

// Watermark tests level against stored high watermark
type Watermark interface {
	IsSafeToSign(pkh string, msg tezos.UnsignedMessage) bool
}

// InMemoryWatermark keep previous operation in memory
type InMemoryWatermark struct {
	watermarks map[string]int32
	mtx        *sync.Mutex
}

// NewInMemoryWatermark create a new Memory watermark
func NewInMemoryWatermark() *InMemoryWatermark {
	return &InMemoryWatermark{
		watermarks: make(map[string]int32),
		mtx:        &sync.Mutex{},
	}
}

// IsSafeToSign return true if this msgID is safe to sign
func (w *InMemoryWatermark) IsSafeToSign(pkh string, msg tezos.UnsignedMessage) bool {
	msgWithChainID, ok := msg.(tezos.MessageWithLevelAndChainID)
	if !ok {
		// watermark is not required
		return true
	}

	msgID := fmt.Sprintf("%s:%s:%s", pkh, msgWithChainID.GetChainID(), msg.MessageKind())
	level := msgWithChainID.GetLevel()

	w.mtx.Lock()
	defer w.mtx.Unlock()

	if val, ok := w.watermarks[msgID]; ok {
		// If new level is bigger than past level allow signing
		if level > val {
			w.watermarks[msgID] = level
			return true
		}
		return false
	}

	w.watermarks[msgID] = level
	return true
}

// IgnoreWatermark watermark that do not validation and return true
type IgnoreWatermark struct {
}

// NewIgnoreWatermark create a new ignore watermark
func NewIgnoreWatermark() *IgnoreWatermark {
	return &IgnoreWatermark{}
}

// IsSafeToSign always return true
func (w *IgnoreWatermark) IsSafeToSign(pkh string, msg tezos.UnsignedMessage) bool {
	return true
}

var (
	_ Watermark = &InMemoryWatermark{}
	_ Watermark = &IgnoreWatermark{}
)
