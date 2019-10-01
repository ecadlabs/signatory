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

// Memory keep previous operation in memory
type Memory struct {
	watermarks map[string]int32
	mtx        *sync.Mutex
}

// NewMemory create a new Memory watermark
func NewMemory() *Memory {
	return &Memory{
		watermarks: make(map[string]int32),
		mtx:        &sync.Mutex{},
	}
}

// IsSafeToSign return true if this msgID is safe to sign
func (w *Memory) IsSafeToSign(pkh string, msg tezos.UnsignedMessage) bool {
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

// Ignore watermark that do not validation and return true
type Ignore struct {
}

// NewIgnore create a new ignore watermark
func NewIgnore() *Ignore {
	return &Ignore{}
}

// IsSafeToSign always return true
func (w *Ignore) IsSafeToSign(pkh string, msg tezos.UnsignedMessage) bool {
	return true
}

var (
	_ Watermark = &Memory{}
	_ Watermark = &Ignore{}
)
