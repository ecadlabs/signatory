package yubi

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"encoding/asn1"
	"fmt"
	"math/big"
	"os"
	"strconv"

	"github.com/certusone/yubihsm-go"
	"github.com/certusone/yubihsm-go/commands"
	"github.com/certusone/yubihsm-go/connector"
	"github.com/ecadlabs/signatory/pkg/config"
	"github.com/ecadlabs/signatory/pkg/cryptoutils"
	"github.com/ecadlabs/signatory/pkg/errors"
	"github.com/ecadlabs/signatory/pkg/vault"
	"gopkg.in/yaml.v3"
)

const (
	envAddress   = "YUBIHSM_CONNECT_ADDRESS"
	envPassword  = "YUBIHSM_PASSWORD"
	envAuthKeyID = "YUBIHSM_AUTH_KEY_ID"
)

// Config contains YubiHSM backend configuration
type Config struct {
	Address   string `yaml:"address" validate:"omitempty,hostport"`
	Password  string `yaml:"password"`
	AuthKeyID uint16 `yaml:"auth_key_id"`
}

func (c *Config) id() string {
	return fmt.Sprintf("%s/%d", c.Address, c.AuthKeyID)
}

type hsmKey struct {
	id  uint16
	pub crypto.PublicKey
}

func (h *hsmKey) PublicKey() crypto.PublicKey { return h.pub }
func (h *hsmKey) ID() string                  { return strconv.FormatUint(uint64(h.id), 10) }

// HSM struct containing information required to interrogate a YubiHSM
type HSM struct {
	session *yubihsm.SessionManager
	conf    *Config
}

// Name returns backend name
func (h *HSM) Name() string {
	return "YubiHSM"
}

// VaultName returns vault name
func (h *HSM) VaultName() string {
	return h.conf.id()
}

type yubihsmStoredKeysIterator struct {
	hsm     *HSM
	objects []commands.Object
	idx     int
}

func parsePublicKey(r *commands.GetPubKeyResponse) (crypto.PublicKey, bool, error) {
	switch r.Algorithm {
	case commands.AlgorithmP256, commands.AlgorithmSecp256k1:
		var curve elliptic.Curve
		switch r.Algorithm {
		case commands.AlgorithmSecp256k1:
			curve = cryptoutils.S256()
		case commands.AlgorithmP256:
			curve = elliptic.P256()
		}

		byteLen := (curve.Params().BitSize + 7) >> 3
		if len(r.KeyData) != 2*byteLen {
			return nil, false, fmt.Errorf("invalid public key length %d for curve %s", len(r.KeyData), curve.Params().Name)
		}
		p := curve.Params().P
		x := new(big.Int).SetBytes(r.KeyData[:byteLen])
		y := new(big.Int).SetBytes(r.KeyData[byteLen:])
		if x.Cmp(p) >= 0 || y.Cmp(p) >= 0 {
			return nil, false, fmt.Errorf("invalid EC point [%X, %X]", x, y)
		}
		if !curve.IsOnCurve(x, y) {
			return nil, false, fmt.Errorf("invalid EC point [%X, %X]", x, y)
		}

		return &ecdsa.PublicKey{
			Curve: curve,
			X:     x,
			Y:     y,
		}, true, nil

	case commands.AlgorighmED25519:
		if len(r.KeyData) != ed25519.PublicKeySize {
			return nil, false, fmt.Errorf("invalid public key length %d ", len(r.KeyData))
		}
		return ed25519.PublicKey(r.KeyData), true, nil
	}

	return nil, false, nil
}

// Next implements vault.StoredKeysIterator
func (y *yubihsmStoredKeysIterator) Next() (key vault.StoredKey, err error) {
	if y.objects == nil {
		command, err := commands.CreateListObjectsCommand(commands.NewObjectTypeOption(commands.ObjectTypeAsymmetricKey))
		res, err := y.hsm.session.SendEncryptedCommand(command)
		if err != nil {
			return nil, fmt.Errorf("(YubiHSM/%s): ListObjects: %v", y.hsm.conf.id(), err)
		}
		listObjectsResponse, ok := res.(*commands.ListObjectsResponse)
		if !ok {
			return nil, fmt.Errorf("(YubiHSM/%s): unexpected response type: %T", y.hsm.conf.id(), res)
		}
		y.objects = listObjectsResponse.Objects
	}

	for {
		if y.idx == len(y.objects) {
			return nil, vault.ErrDone
		}

		obj := y.objects[y.idx]
		command, err := commands.CreateGetPubKeyCommand(obj.ObjectID)
		res, err := y.hsm.session.SendEncryptedCommand(command)
		if err != nil {
			return nil, fmt.Errorf("(YubiHSM/%s): GetPubKey: %v", y.hsm.conf.id(), err)
		}

		pubKeyResponse, ok := res.(*commands.GetPubKeyResponse)
		if !ok {
			return nil, fmt.Errorf("(YubiHSM/%s): unexpected response type: %T", y.hsm.conf.id(), res)
		}
		y.idx++

		pub, ok, err := parsePublicKey(pubKeyResponse)
		if err != nil {
			return nil, fmt.Errorf("(YubiHSM/%s): %v", y.hsm.conf.id(), err)
		}
		if !ok {
			continue // Skip
		}

		return &hsmKey{
			pub: pub,
			id:  obj.ObjectID,
		}, nil
	}
}

// ListPublicKeys list all public key from connected Yubi HSM
func (h *HSM) ListPublicKeys(ctx context.Context) vault.StoredKeysIterator {
	return &yubihsmStoredKeysIterator{hsm: h}
}

// GetPublicKey returns a public key by given ID
func (h *HSM) GetPublicKey(ctx context.Context, keyID string) (vault.StoredKey, error) {
	id, err := strconv.ParseUint(keyID, 10, 16)
	if err != nil {
		return nil, fmt.Errorf("(YubiHSM/%s): %v", h.conf.id(), err)
	}

	command, err := commands.CreateGetPubKeyCommand(uint16(id))
	res, err := h.session.SendEncryptedCommand(command)
	if err != nil {
		return nil, fmt.Errorf("(YubiHSM/%s): GetPubKey: %v", h.conf.id(), err)
	}

	pubKeyResponse, ok := res.(*commands.GetPubKeyResponse)
	if !ok {
		return nil, fmt.Errorf("(YubiHSM/%s): unexpected response type: %T", h.conf.id(), res)
	}

	pub, ok, err := parsePublicKey(pubKeyResponse)
	if err != nil {
		return nil, fmt.Errorf("(YubiHSM/%s): %v", h.conf.id(), err)
	}
	if !ok {
		return nil, fmt.Errorf("(YubiHSM/%s): unsupported key type: %d", h.conf.id(), pubKeyResponse.Algorithm)
	}

	return &hsmKey{
		pub: pub,
		id:  uint16(id),
	}, nil
}

func (h *HSM) signECDSA(ctx context.Context, digest []byte, id uint16) (*cryptoutils.ECDSASignature, error) {
	command, err := commands.CreateSignDataEcdsaCommand(id, digest)
	if err != nil {
		return nil, fmt.Errorf("(YubiHSM/%s): %v", h.conf.id(), err)
	}
	res, err := h.session.SendEncryptedCommand(command)
	if err != nil {
		return nil, fmt.Errorf("(YubiHSM/%s): SignDataEcdsa: %v", h.conf.id(), err)
	}

	ecdsaResponse, ok := res.(*commands.SignDataEcdsaResponse)
	if !ok {
		return nil, fmt.Errorf("(YubiHSM/%s): unexpected response type: %T", h.conf.id(), res)
	}

	var sig cryptoutils.ECDSASignature
	if _, err = asn1.Unmarshal(ecdsaResponse.Signature, &sig); err != nil {
		return nil, fmt.Errorf("(YubiHSM/%s): %v", h.conf.id(), err)
	}

	return &sig, nil
}

func (h *HSM) signED25519(ctx context.Context, digest []byte, id uint16) (cryptoutils.ED25519Signature, error) {
	command, err := commands.CreateSignDataEddsaCommand(id, digest)
	if err != nil {
		return nil, fmt.Errorf("(YubiHSM/%s): %v", h.conf.id(), err)
	}
	res, err := h.session.SendEncryptedCommand(command)
	if err != nil {
		return nil, fmt.Errorf("(YubiHSM/%s): SignDataEddsa: %v", h.conf.id(), err)
	}

	eddsaResponse, ok := res.(*commands.SignDataEddsaResponse)
	if !ok {
		return nil, fmt.Errorf("(YubiHSM/%s): unexpected response type: %T", h.conf.id(), res)
	}

	if len(eddsaResponse.Signature) != ed25519.SignatureSize {
		return nil, fmt.Errorf("(YubiHSM/%s): invalid ED25519 signature length: %d", h.conf.id(), len(eddsaResponse.Signature))
	}

	return cryptoutils.ED25519Signature(eddsaResponse.Signature), nil
}

// Sign performs signing operation
func (h *HSM) Sign(ctx context.Context, digest []byte, k vault.StoredKey) (sig cryptoutils.Signature, err error) {
	key, ok := k.(*hsmKey)
	if !ok {
		return nil, fmt.Errorf("(YubiHSM/%s): not a YubiHSM key: %T", h.conf.id(), k)
	}

	switch key.pub.(type) {
	case *ecdsa.PublicKey:
		return h.signECDSA(ctx, digest, key.id)
	case ed25519.PublicKey:
		return h.signED25519(ctx, digest, key.id)
	}

	return nil, fmt.Errorf("(YubiHSM/%s): unexpected key type: %T", h.conf.id(), key.pub)
}

var echoMessage = []byte("health")

// Ready implements vault.ReadinessChecker
func (h *HSM) Ready(ctx context.Context) (bool, error) {
	command, err := commands.CreateEchoCommand(echoMessage)
	if err != nil {
		return false, fmt.Errorf("(YubiHSM/%s): %v", h.conf.id(), err)
	}

	res, err := h.session.SendEncryptedCommand(command)
	if err != nil {
		return false, nil // Don't return an error
	}

	echoResponse, ok := res.(*commands.EchoResponse)
	if !ok {
		return false, fmt.Errorf("(YubiHSM/%s): unexpected response type: %T", h.conf.id(), res)
	}

	if !bytes.Equal(echoResponse.Data, echoMessage) {
		return false, fmt.Errorf("(YubiHSM/%s): echoed data is invalid", h.conf.id())
	}

	return true, nil
}

// New creates new YubiHSM backend
func New(ctx context.Context, config *Config) (*HSM, error) {
	c := *config
	if c.Address == "" {
		c.Address = os.Getenv(envAddress)
	}

	if c.Password == "" {
		c.Password = os.Getenv(envPassword)
	}

	if c.AuthKeyID == 0 {
		v, err := strconv.ParseUint(os.Getenv(envAuthKeyID), 10, 16)
		if err != nil {
			return nil, fmt.Errorf("(YubiHSM): %v", err)
		}
		c.AuthKeyID = uint16(v)
	}

	conn := connector.NewHTTPConnector(config.Address)
	sm, err := yubihsm.NewSessionManager(conn, config.AuthKeyID, config.Password)
	if err != nil {
		return nil, err
	}

	return &HSM{
		session: sm,
		conf:    &c,
	}, nil
}

func init() {
	vault.RegisterVault("yubihsm", func(ctx context.Context, node *yaml.Node) (vault.Vault, error) {
		var conf Config
		if node == nil || node.Kind == 0 {
			return nil, errors.New("(YubiHSM): config is missing")
		}
		if err := node.Decode(&conf); err != nil {
			return nil, err
		}

		if err := config.Validator().Struct(&conf); err != nil {
			return nil, err
		}

		return New(ctx, &conf)
	})
}
