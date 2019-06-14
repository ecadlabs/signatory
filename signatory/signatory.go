package signatory

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/big"

	log "github.com/sirupsen/logrus"

	"github.com/ecadlabs/signatory/config"
	"github.com/ecadlabs/signatory/tezos"
)

var (
	// ErrVaultNotFound error return when a vault is not found
	ErrVaultNotFound = fmt.Errorf("This key not found in any vault")
	// ErrNotSafeToSign error returned when an operation is a potential duplicate
	ErrNotSafeToSign = fmt.Errorf("Not safe to sign")
)

// JWK struct containing a standard key format
type JWK struct {
	KeyType string `json:"kty"`
	D       string `json:"d"`
	X       string `json:"x"`
	Y       string `json:"y"`
	Curve   string `json:"crv"`
}

type NotifySigning func(address string, vault string, kind string)

// PublicKey alias for an array of byte
type PublicKey = []byte

type StoredKey interface {
	Curve() string
	PublicKey() []byte
	ID() string
}

// ImportedKey struct containing information about an imported key
type ImportedKey struct {
	Hash  string
	KeyID string
}

// Vault interface that represent a secure key store
type Vault interface {
	GetPublicKey(keyID string) (StoredKey, error)
	ListPublicKeys() ([]StoredKey, error)
	Sign(digest []byte, key StoredKey) ([]byte, error)
	Import(jwk *JWK) (string, error)
	Name() string
}

// KeyPair interface that represent an elliptic curve key pair
type KeyPair interface {
	X() []byte
	Y() []byte
	D() []byte
	CurveName() string
}

// Watermark interface for service that allow double bake check
type Watermark interface {
	IsSafeToSign(msgID string, level *big.Int) bool
}

type vaultKeyIDPair struct {
	vault Vault
	key   StoredKey
}

type HashVaultStore = map[string]vaultKeyIDPair

func (s *Signatory) addKeyMap(hash string, key StoredKey, vault Vault) {
	s.hashVaultStore[hash] = vaultKeyIDPair{key: key, vault: vault}
}

// Signatory is a struct coordinate signatory action and select vault according to the key being used
type Signatory struct {
	vaults         []Vault
	config         *config.TezosConfig
	notifySigning  NotifySigning
	watermark      Watermark
	hashVaultStore HashVaultStore
}

// NewSignatory return a new signatory struct
func NewSignatory(
	vaults []Vault,
	config *config.TezosConfig,
	notify NotifySigning,
	watermark Watermark,
) *Signatory {
	return &Signatory{
		vaults:         vaults,
		config:         config,
		hashVaultStore: make(HashVaultStore),
		notifySigning:  notify,
		watermark:      watermark,
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

func (s *Signatory) validateMessage(msg *tezos.Message) error {
	err := msg.Validate()

	if err != nil {
		return err
	}

	err = msg.MatchFilter(s.config)

	if err != nil {
		return err
	}

	return nil
}

// Sign ask the vault to sign a message with the private key associated to keyHash
func (s *Signatory) Sign(keyHash string, message []byte) (string, error) {
	log.Infof("Signing for key: %s\n", keyHash)
	log.Debugf("About to sign raw bytes hex.EncodeToString(message): %s\n", hex.EncodeToString(message))

	msg := tezos.ParseMessage(message)

	if err := s.validateMessage(msg); err != nil {
		return "", err
	}

	if msg.RequireWatermark() {
		watermark, level := msg.Watermark(keyHash)
		if !s.watermark.IsSafeToSign(watermark, level) {
			return "", ErrNotSafeToSign
		}
	}

	vault := s.getVaultFromKeyHash(keyHash)

	if vault == nil {
		return "", ErrVaultNotFound
	}

	// Not nil if vault found
	storedKey := s.getKeyFromKeyHash(keyHash)

	digest := tezos.DigestFunc(message)
	sig, err := vault.Sign(digest[:], storedKey)

	log.Debugf("Signed bytes hex.EncodeToString(bytes): %s\n", hex.EncodeToString(sig))

	if err != nil {
		return "", err
	}

	encodedSig := tezos.EncodeSig(keyHash, sig)

	log.Debugf("Encoded signature: %s\n", encodedSig)

	s.notifySigning(keyHash, vault.Name(), msg.Type())

	log.Infof("Signed %s successfully", msg.Type())

	return encodedSig, nil
}

// ListPublicKeyHash retrieve the list of all public key hash supported by the current configuration
func (s *Signatory) ListPublicKeyHash() ([]string, error) {
	results := []string{}
	for _, vault := range s.vaults {
		pubKeys, err := vault.ListPublicKeys()

		if err != nil {
			return nil, err
		}

		for _, key := range pubKeys {
			encoded := tezos.EncodePubKeyHash(key.PublicKey(), key.Curve())
			results = append(results, encoded)

			s.addKeyMap(encoded, key, vault)
		}
	}
	return results, nil
}

// GetPublicKey retrieve the public key from a vault
func (s *Signatory) GetPublicKey(keyHash string) (string, error) {
	vault := s.getVaultFromKeyHash(keyHash)

	if vault == nil {
		return "", ErrVaultNotFound
	}

	key := s.getKeyFromKeyHash(keyHash)

	log.Debugf("Fetching public key for: %s\n", keyHash)

	pubKey, err := vault.GetPublicKey(key.ID())
	if err != nil {
		return "", err
	}
	return tezos.EncodePubKey(keyHash, pubKey.PublicKey()), nil
}

// Import a keyPair inside the vault
func (s *Signatory) Import(pubkey string, secretKey string, vault Vault) (*ImportedKey, error) {
	keyPair := tezos.NewKeyPair(pubkey, secretKey)
	err := keyPair.Validate()

	if err != nil {
		return nil, err
	}

	jwk, err := s.ToJWK(keyPair)

	if err != nil {
		return nil, err
	}

	keyID, err := vault.Import(jwk)

	if err != nil {
		return nil, err
	}

	hash, err := keyPair.PubKeyHash()

	if err != nil {
		return nil, err
	}

	importedKey := &ImportedKey{
		KeyID: keyID,
		Hash:  hash,
	}

	return importedKey, nil
}

// ToJWK Convert a keyPair to a JWK
func (s *Signatory) ToJWK(k KeyPair) (*JWK, error) {
	return &JWK{
		X:       base64.StdEncoding.EncodeToString(k.X()),
		Y:       base64.StdEncoding.EncodeToString(k.Y()),
		D:       base64.StdEncoding.EncodeToString(k.D()),
		KeyType: "EC",
		Curve:   k.CurveName(),
	}, nil
}
