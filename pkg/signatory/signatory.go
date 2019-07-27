package signatory

import (
	"context"
	"encoding/hex"
	"fmt"
	"math/big"
	"sync"

	log "github.com/sirupsen/logrus"

	"github.com/ecadlabs/signatory/pkg/config"
	"github.com/ecadlabs/signatory/pkg/crypto"
	"github.com/ecadlabs/signatory/pkg/tezos"
)

var (
	// ErrVaultNotFound error return when a vault is not found
	ErrVaultNotFound = fmt.Errorf("This key not found in any vault")
	// ErrNotSafeToSign error returned when an operation is a potential duplicate
	ErrNotSafeToSign = fmt.Errorf("Not safe to sign")
)

const (
	LogPKH       = "pkh"
	LogVault     = "vault"
	LogVaultName = "vault_name"
	LogOp        = "op"
	LogKind      = "kind"
	LogKeyID     = "key_id"
)

// SignInterceptor is an observer function for signing request
type SignInterceptor func(opt *SignInterceptorOptions, sing func() error) error

// SignInterceptorOptions contains SignInterceptor arguments to avoid confusion
type SignInterceptorOptions struct {
	Address string
	Vault   string
	Op      string
	Kind    string
}

// PublicKey alias for an array of byte
type PublicKey = []byte

type StoredKey interface {
	Curve() string
	PublicKey() []byte
	ID() string
}

// Vault interface that represent a secure key store
type Vault interface {
	GetPublicKey(ctx context.Context, keyID string) (StoredKey, error)
	ListPublicKeys(ctx context.Context) ([]StoredKey, error)
	Sign(ctx context.Context, digest []byte, key StoredKey) ([]byte, error)
	Name() string
}

// VaultNamer might be implemented by some backends which can handle multiple vaults under single account
type VaultNamer interface {
	VaultName() string
}

// Watermark interface for service that allow double bake check
type Watermark interface {
	IsSafeToSign(msgID string, level *big.Int) bool
}

type keyVaultPair struct {
	vault Vault
	key   StoredKey
}

// Signatory is a struct coordinate signatory action and select vault according to the key being used
type Signatory struct {
	vaults         []Vault
	config         config.TezosConfig
	interceptor    SignInterceptor
	watermark      Watermark
	logger         log.FieldLogger
	hashVaultCache map[string]*keyVaultPair
	mtx            sync.Mutex
}

// NewSignatory return a new signatory struct
func NewSignatory(
	vaults []Vault,
	config config.TezosConfig,
	interceptor SignInterceptor,
	watermark Watermark,
	logger log.FieldLogger,
) (s *Signatory) {
	s = &Signatory{
		vaults:         vaults,
		config:         config,
		hashVaultCache: make(map[string]*keyVaultPair),
		interceptor:    interceptor,
		watermark:      watermark,
		logger:         logger,
	}

	if s.logger == nil {
		s.logger = log.StandardLogger()
	}

	return
}

func isSupportedCurve(curve string) bool {
	return curve == crypto.CurveP256 || curve == crypto.CurveP256K || curve == crypto.CurveED25519
}

// IsAllowed returns true if keyHash is listed in configuration
func (s *Signatory) IsAllowed(keyHash string) bool {
	for key := range s.config {
		if key == keyHash {
			return true
		}
	}
	return false
}

func (s *Signatory) FetchPolicyOrDefault(keyHash string) *config.TezosPolicy {
	if val, ok := s.config[keyHash]; ok {
		return &val
	}
	return &config.TezosPolicy{
		AllowedOperations: []string{tezos.OpEndorsement, tezos.OpBlock},
		AllowedKinds:      []string{},
	}
}

func (s *Signatory) validateMessage(msg *tezos.Message, policy *config.TezosPolicy) error {
	err := msg.Validate()

	if err != nil {
		return err
	}

	err = msg.MatchFilter(policy)

	if err != nil {
		return err
	}

	return nil
}

func (s *Signatory) cacheLookup(ctx context.Context, keyHash string, update bool) (*keyVaultPair, error) {
	s.mtx.Lock()
	if v, ok := s.hashVaultCache[keyHash]; ok {
		s.mtx.Unlock()
		return v, nil
	}
	s.mtx.Unlock()

	if !update {
		return nil, nil
	}

	// Rescan
	cache, err := s.listPublicKeyHash(ctx)
	if err != nil {
		return nil, err
	}

	s.mtx.Lock()
	defer s.mtx.Unlock()

	s.hashVaultCache = cache
	if v, ok := s.hashVaultCache[keyHash]; ok {
		return v, nil
	}
	return nil, nil
}

// GetCachedPublicKey returns public key object and vault for the given hash from the cache. The latter is not updated.
func (s *Signatory) GetCachedPublicKey(ctx context.Context, keyHash string) (Vault, StoredKey, error) {
	cached, err := s.cacheLookup(ctx, keyHash, false)
	if err != nil {
		return nil, nil, err
	}

	if cached == nil {
		return nil, nil, ErrVaultNotFound
	}

	return cached.vault, cached.key, nil
}

// Sign ask the vault to sign a message with the private key associated to keyHash
func (s *Signatory) Sign(ctx context.Context, keyHash string, message []byte) (string, error) {
	l := s.logger.WithField(LogPKH, keyHash)

	if !s.IsAllowed(keyHash) {
		err := fmt.Errorf("%s is not listed in config", keyHash)
		l.WithField("raw", hex.EncodeToString(message)).Error(err)
		return "", err
	}

	policy := s.FetchPolicyOrDefault(keyHash)

	msg := tezos.ParseMessage(message)
	if err := s.validateMessage(msg, policy); err != nil {
		l.WithField("raw", hex.EncodeToString(message)).Error(err)
		return "", err
	}

	l = l.WithFields(log.Fields{
		LogOp:   msg.Type(),
		LogKind: msg.Kind(),
	})

	cached, err := s.cacheLookup(ctx, keyHash, true)
	if err != nil {
		l.Error(err)
		return "", err
	}

	if cached == nil {
		l.Error("Vault not found")
		return "", ErrVaultNotFound
	}

	logfields := log.Fields{
		LogVault: cached.vault.Name(),
	}
	if n, ok := cached.vault.(VaultNamer); ok {
		logfields[LogVaultName] = n.VaultName()
	}
	l = l.WithFields(logfields)

	l.Info("Requesting signing operation")

	level := log.DebugLevel
	if policy.LogPayloads {
		level = log.InfoLevel
	}
	l.WithField("raw", hex.EncodeToString(message)).Info(level, "About to sign raw bytes")

	if msg.RequireWatermark() {
		watermark, level := msg.Watermark(keyHash)
		if !s.watermark.IsSafeToSign(watermark, level) {
			return "", ErrNotSafeToSign
		}
	}

	// Not nil if vault found
	digest := tezos.DigestFunc(message)

	var sig []byte

	if s.interceptor != nil {
		err = s.interceptor(&SignInterceptorOptions{
			Address: keyHash,
			Vault:   cached.vault.Name(),
			Op:      msg.Type(),
			Kind:    msg.Kind(),
		}, func() (err error) {
			sig, err = cached.vault.Sign(ctx, digest[:], cached.key)
			return err
		})
	} else {
		sig, err = cached.vault.Sign(ctx, digest[:], cached.key)
	}

	if err != nil {
		return "", err
	}

	l.WithField("raw", hex.EncodeToString(sig)).Debug("Signed bytes")

	fmt.Printf("%s\n", hex.EncodeToString(sig))
	encodedSig := tezos.EncodeSig(keyHash, sig)

	l.Debugf("Encoded signature: %s", encodedSig)
	l.Infof("Signed %s successfully", msg.Type())

	return encodedSig, nil
}

func (s *Signatory) listPublicKeyHash(ctx context.Context) (map[string]*keyVaultPair, error) {
	cache := make(map[string]*keyVaultPair)

	for _, vault := range s.vaults {
		pubKeys, err := vault.ListPublicKeys(ctx)
		if err != nil {
			return nil, err
		}

		for _, key := range pubKeys {
			if isSupportedCurve(key.Curve()) {
				encoded := tezos.EncodePubKeyHash(key.PublicKey(), key.Curve())
				cache[encoded] = &keyVaultPair{key: key, vault: vault}
			}
		}
	}
	return cache, nil
}

// ListPublicKeyHash retrieve the list of all public key hash supported by the current configuration
func (s *Signatory) ListPublicKeyHash(ctx context.Context) ([]string, error) {
	cache, err := s.listPublicKeyHash(ctx)
	if err != nil {
		return nil, err
	}

	// Replace the cache
	s.mtx.Lock()
	s.hashVaultCache = cache
	s.mtx.Unlock()

	results := make([]string, 0, len(cache))
	for keyHash := range cache {
		results = append(results, keyHash)
	}

	return results, nil
}

// GetPublicKey retrieve the public key from a vault
func (s *Signatory) GetPublicKey(ctx context.Context, keyHash string) (string, error) {
	cached, err := s.cacheLookup(ctx, keyHash, true)
	if err != nil {
		return "", err
	}

	if cached == nil {
		return "", ErrVaultNotFound
	}

	logfields := log.Fields{
		LogPKH:   keyHash,
		LogVault: cached.vault.Name(),
	}
	if n, ok := cached.vault.(VaultNamer); ok {
		logfields[LogVaultName] = n.VaultName()
	}
	l := s.logger.WithFields(logfields)

	l.Debugf("Fetching public key for: %s", keyHash)

	pubKey, err := cached.vault.GetPublicKey(ctx, cached.key.ID())
	if err != nil {
		return "", err
	}
	return tezos.EncodePubKey(keyHash, pubKey.PublicKey()), nil
}
