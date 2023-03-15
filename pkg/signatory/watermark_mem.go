package signatory

import (
	"sync"

	tz "github.com/ecadlabs/gotez"
	"github.com/ecadlabs/signatory/pkg/signatory/request"
)

// InMemoryWatermark keep previous operation in memory
type InMemoryWatermark struct {
	chains chainMap
	mtx    sync.Mutex
}

// IsSafeToSign return true if this msgID is safe to sign
func (w *InMemoryWatermark) IsSafeToSign(pkh tz.PublicKeyHash, req request.SignRequest) error {
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

	delegates, ok := w.chains[*watermark.Chain]
	if ok {
		if wm, ok := delegates.Get(pkh); ok {
			if !watermark.Validate(wm) {
				return ErrWatermark
			}
		}
	} else {
		delegates = make(delegateMap)
		w.chains[*watermark.Chain] = delegates
	}
	delegates.Insert(pkh, watermark.Stored())

	return nil
}

var _ Watermark = (*InMemoryWatermark)(nil)
