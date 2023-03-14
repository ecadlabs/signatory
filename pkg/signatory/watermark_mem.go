package signatory

import (
	"sync"

	"github.com/ecadlabs/signatory/pkg/signatory/request"
)

// InMemoryWatermark keep previous operation in memory
type InMemoryWatermark struct {
	chains chainMap
	mtx    sync.Mutex
}

// IsSafeToSign return true if this msgID is safe to sign
func (w *InMemoryWatermark) IsSafeToSign(pkh string, req request.SignRequest) error {
	m, ok := req.(request.WithWatermark)
	if !ok {
		// watermark is not required
		return nil
	}
	watermark := m.Watermark()

	w.mtx.Lock()
	defer w.mtx.Unlock()

	if w.chains == nil {
		w.chains = make(chainMap)
	}

	delegates, ok := w.chains[watermark.Chain.String()]
	if ok {
		if wm, ok := delegates[pkh]; ok {
			if !watermark.Validate(wm) {
				return ErrWatermark
			}
		}
	} else {
		delegates = make(watermarkMap)
		w.chains[watermark.Chain.String()] = delegates
	}
	delegates[pkh] = watermark.Stored()

	return nil
}

var _ Watermark = (*InMemoryWatermark)(nil)
