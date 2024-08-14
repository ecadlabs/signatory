package watermark

import (
	"context"
	"fmt"

	"github.com/ecadlabs/gotez/v2/crypt"
	"github.com/ecadlabs/gotez/v2/protocol"
	"gopkg.in/yaml.v3"
)

// Watermark tests level against stored high watermark
type Watermark interface {
	IsSafeToSign(ctx context.Context, pkh crypt.PublicKeyHash, req protocol.SignRequest, digest *crypt.Digest) error
}

// Ignore watermark that do not validation and return true
type Ignore struct{}

// IsSafeToSign always return true
func (w Ignore) IsSafeToSign(context.Context, crypt.PublicKeyHash, protocol.SignRequest, *crypt.Digest) error {
	return nil
}

var _ Watermark = (*Ignore)(nil)

type Factory interface {
	New(ctx context.Context, name string, conf *yaml.Node) (Watermark, error)
}

type newWMBackendFunc func(ctx context.Context, conf *yaml.Node) (Watermark, error)

type registry map[string]newWMBackendFunc

func (r registry) New(ctx context.Context, name string, conf *yaml.Node) (Watermark, error) {
	if newFunc, ok := r[name]; ok {
		return newFunc(ctx, conf)
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
