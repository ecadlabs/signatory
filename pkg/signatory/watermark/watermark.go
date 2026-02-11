package watermark

import (
	"context"
	"fmt"

	"github.com/ecadlabs/gotez/v2/crypt"
	"github.com/ecadlabs/gotez/v2/protocol/core"
	"github.com/ecadlabs/signatory/pkg/config"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
)

// Watermark tests level against stored high watermark
type Watermark interface {
	IsSafeToSign(ctx context.Context, pkh crypt.PublicKeyHash, req core.SignRequest, digest *crypt.Digest) error
	Backend() string
}

// watermarkImpl is the interface that backends implement (without Backend())
type watermarkImpl interface {
	IsSafeToSign(ctx context.Context, pkh crypt.PublicKeyHash, req core.SignRequest, digest *crypt.Digest) error
}

// named wraps a watermarkImpl with its registered name
type namedWatermark struct {
	watermarkImpl
	name string
}

func (n *namedWatermark) Backend() string {
	return n.name
}

// Ignore watermark that do not validation and return true
type Ignore struct{}

// IsSafeToSign always return true
func (w Ignore) IsSafeToSign(context.Context, crypt.PublicKeyHash, core.SignRequest, *crypt.Digest) error {
	return nil
}

// Backend returns the backend name
func (w Ignore) Backend() string {
	return "none"
}

var _ Watermark = (*Ignore)(nil)

type Factory interface {
	New(ctx context.Context, name string, conf *yaml.Node, global config.GlobalContext) (Watermark, error)
}

type newWMBackendFunc func(ctx context.Context, conf *yaml.Node, global config.GlobalContext) (watermarkImpl, error)

type registry map[string]newWMBackendFunc

func (r registry) New(ctx context.Context, name string, conf *yaml.Node, global config.GlobalContext) (Watermark, error) {
	if newFunc, ok := r[name]; ok {
		log.WithField("backend", name).Info("Initializing watermark backend")
		impl, err := newFunc(ctx, conf, global)
		if err != nil {
			return nil, err
		}
		return &namedWatermark{watermarkImpl: impl, name: name}, nil
	}
	return nil, fmt.Errorf("unknown watermark backend: %s", name)
}

var wmRegistry = make(registry)

func RegisterWatermark(name string, newFunc newWMBackendFunc) {
	wmRegistry[name] = newFunc
}

func Registry() Factory {
	return wmRegistry
}
