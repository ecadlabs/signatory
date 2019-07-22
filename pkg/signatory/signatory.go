package signatory

import (
	"context"
	"encoding/hex"
	"fmt"
	"math/big"

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
	logPKH       = "pkh"
	logVault     = "vault"
	logVaultName = "vault_name"
	logOp        = "op"
	logKind      = "kind"
	logKeyID     = "key_id"
)

// SingInterceptor is an observer function for signing request
type SingInterceptor func(opt *SingInterceptorOptions, sing func() error) error

// SingInterceptorOptions contains SingInterceptor arguments to avoid confusion
type SingInterceptorOptions struct {
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

type vaultKeyIDPair struct {
	vault Vault
	key   StoredKey
}

// HashVaultStore store the id and the vault of each key
type HashVaultStore = map[string]vaultKeyIDPair

func (s *Signatory) addKeyMap(hash string, key StoredKey, vault Vault) {
	s.hashVaultStore[hash] = vaultKeyIDPair{key: key, vault: vault}
}

// Signatory is a struct coordinate signatory action and select vault according to the key being used
type Signatory struct {
	vaults         []Vault
	config         config.TezosConfig
	interceptor    SingInterceptor
	watermark      Watermark
	hashVaultStore HashVaultStore
	logger         log.FieldLogger
}

// NewSignatory return a new signatory struct
func NewSignatory(
	vaults []Vault,
	config config.TezosConfig,
	interceptor SingInterceptor,
	watermark Watermark,
	logger log.FieldLogger,
) (s *Signatory) {
	s = &Signatory{
		vaults:         vaults,
		config:         config,
		hashVaultStore: make(HashVaultStore),
		interceptor:    interceptor,
		watermark:      watermark,
		logger:         logger,
	}

	if s.logger == nil {
		s.logger = log.StandardLogger()
	}

	return
}

func IsSupportedCurve(curve string) bool {
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

func (s *Signatory) getVaultFromKeyHash(keyHash string) Vault {
	if pair, ok := s.hashVaultStore[keyHash]; ok {
		return pair.vault
	}
	return nil
}

func (s *Signatory) getKeyFromKeyHash(keyHash string) StoredKey {
	if pair, ok := s.hashVaultStore[keyHash]; ok {
		return pair.key
	}
	return nil
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

// Sign ask the vault to sign a message with the private key associated to keyHash
func (s *Signatory) Sign(ctx context.Context, keyHash string, message []byte) (string, error) {
	if !s.IsAllowed(keyHash) {
		return "", fmt.Errorf("%s is not listed in config", keyHash)
	}

	policy := s.FetchPolicyOrDefault(keyHash)

	msg := tezos.ParseMessage(message)
	if err := s.validateMessage(msg, policy); err != nil {
		return "", err
	}

	l := s.logger.WithFields(log.Fields{
		logPKH:  keyHash,
		logOp:   msg.Type(),
		logKind: msg.Kind(),
	})

	vault := s.getVaultFromKeyHash(keyHash)
	if vault == nil {
		l.Error("Vault not found")
		return "", ErrVaultNotFound
	}

	logfields := log.Fields{
		logVault: vault.Name(),
	}
	if n, ok := vault.(VaultNamer); ok {
		logfields[logVaultName] = n.VaultName()
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
	storedKey := s.getKeyFromKeyHash(keyHash)
	digest := tezos.DigestFunc(message)

	var (
		sig []byte
		err error
	)

	if s.interceptor != nil {
		err = s.interceptor(&SingInterceptorOptions{
			Address: keyHash,
			Vault:   vault.Name(),
			Op:      msg.Type(),
			Kind:    msg.Kind(),
		}, func() (err error) {
			sig, err = vault.Sign(ctx, digest[:], storedKey)
			return err
		})
	} else {
		sig, err = vault.Sign(ctx, digest[:], storedKey)
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

// ListPublicKeyHash retrieve the list of all public key hash supported by the current configuration
func (s *Signatory) ListPublicKeyHash(ctx context.Context) ([]string, error) {
	results := []string{}
	for _, vault := range s.vaults {
		pubKeys, err := vault.ListPublicKeys(ctx)

		if err != nil {
			return nil, err
		}

		for _, key := range pubKeys {
			if IsSupportedCurve(key.Curve()) {
				encoded := tezos.EncodePubKeyHash(key.PublicKey(), key.Curve())
				results = append(results, encoded)
				s.addKeyMap(encoded, key, vault)

			}
		}
	}
	return results, nil
}

// GetPublicKey retrieve the public key from a vault
func (s *Signatory) GetPublicKey(ctx context.Context, keyHash string) (string, error) {
	vault := s.getVaultFromKeyHash(keyHash)
	if vault == nil {
		return "", ErrVaultNotFound
	}

	logfields := log.Fields{
		logPKH:   keyHash,
		logVault: vault.Name(),
	}
	if n, ok := vault.(VaultNamer); ok {
		logfields[logVaultName] = n.VaultName()
	}
	l := s.logger.WithFields(logfields)

	key := s.getKeyFromKeyHash(keyHash)

	l.Debugf("Fetching public key for: %s", keyHash)

	pubKey, err := vault.GetPublicKey(ctx, key.ID())
	if err != nil {
		return "", err
	}
	return tezos.EncodePubKey(keyHash, pubKey.PublicKey()), nil
}
