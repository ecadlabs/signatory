package tezos

import (
	"sync"

	tz "github.com/ecadlabs/gotez"
	"github.com/ecadlabs/signatory/pkg/crypt"
	"github.com/ecadlabs/signatory/pkg/tezos/request"
)

// InMemoryWatermark keep previous operation in memory
type InMemoryWatermark struct {
	chains map[tz.ChainID]delegateMap
	mtx    sync.Mutex
}

// IsSafeToSign return true if this msgID is safe to sign
func (w *InMemoryWatermark) IsSafeToSign(pkh crypt.PublicKeyHash, req request.SignRequest, digest *crypt.Digest) error {
	w.mtx.Lock()
	defer w.mtx.Unlock()
	return w.isSafeToSignUnlocked(pkh, req, digest)
}

func (w *InMemoryWatermark) isSafeToSignUnlocked(pkh crypt.PublicKeyHash, req request.SignRequest, digest *crypt.Digest) error {
	m, ok := req.(request.WithWatermark)
	if !ok {
		// watermark is not required
		return nil
	}

	if w.chains == nil {
		w.chains = make(map[tz.ChainID]delegateMap)
	}

	delegates, ok := w.chains[*m.GetChainID()]
	if !ok {
		delegates = make(delegateMap)
		w.chains[*m.GetChainID()] = delegates
	}

	requests, ok := delegates.Get(pkh)
	if !ok {
		requests = make(requestMap)
		delegates.Insert(pkh, requests)
	}

	watermark := request.NewWatermark(m, digest)
	if stored, ok := requests[req.RequestKind()]; ok {
		if !watermark.Validate(stored) {
			return ErrWatermark
		}
	}
	requests[m.RequestKind()] = watermark
	return nil
}

var _ Watermark = (*InMemoryWatermark)(nil)
