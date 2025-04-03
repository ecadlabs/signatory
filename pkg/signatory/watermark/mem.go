package watermark

import (
	"context"
	"sync"

	tz "github.com/ecadlabs/gotez/v2"
	"github.com/ecadlabs/gotez/v2/crypt"
	"github.com/ecadlabs/gotez/v2/protocol"
	"github.com/ecadlabs/signatory/pkg/config"
	"github.com/ecadlabs/signatory/pkg/signatory/request"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
)

// InMemory keep previous operation in memory
type InMemory struct {
	chains map[tz.ChainID]delegateMap
	mtx    sync.Mutex
}

// IsSafeToSign return true if this msgID is safe to sign
func (w *InMemory) IsSafeToSign(ctx context.Context, pkh crypt.PublicKeyHash, req protocol.SignRequest, digest *crypt.Digest) error {
	w.mtx.Lock()
	defer w.mtx.Unlock()
	return w.isSafeToSignUnlocked(pkh, req, digest)
}

func (w *InMemory) isSafeToSignUnlocked(pkh crypt.PublicKeyHash, req protocol.SignRequest, digest *crypt.Digest) error {
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
	if stored, ok := requests[req.SignRequestKind()]; ok {
		if !watermark.Validate(stored) {
			log.WithFields(log.Fields{
				"chain_id":     m.GetChainID().String(),
				"pkh":          pkh.String(),
				"request":      req.SignRequestKind(),
			}).Info("Signatory prevented double baking by validating watermark")
			return ErrWatermark
		}
	}
	requests[m.SignRequestKind()] = watermark
	return nil
}

func init() {
	RegisterWatermark("mem", func(context.Context, *yaml.Node, *config.Config) (Watermark, error) {
		return new(InMemory), nil
	})
}
