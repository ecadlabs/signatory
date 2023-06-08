package yubi

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/elliptic"
	"encoding/asn1"
	"fmt"
	"math/big"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/certusone/yubihsm-go"
	"github.com/certusone/yubihsm-go/commands"
	"github.com/certusone/yubihsm-go/connector"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/ecadlabs/signatory/pkg/config"
	"github.com/ecadlabs/signatory/pkg/crypt"
	"github.com/ecadlabs/signatory/pkg/errors"
	"github.com/ecadlabs/signatory/pkg/utils"
	"github.com/ecadlabs/signatory/pkg/vault"
	"gopkg.in/yaml.v3"
)

const (
	envAddress          = "YUBIHSM_CONNECT_ADDRESS"
	envPassword         = "YUBIHSM_PASSWORD"
	envAuthKeyID        = "YUBIHSM_AUTH_KEY_ID"
	envKeyImportDomains = "YUBIHSM_KEY_IMPORT_DOMAINS"
)

const defaultDomains = 1

// Config contains YubiHSM backend configuration
type Config struct {
	Address          string `yaml:"address" validate:"omitempty,hostname_port"`
	Password         string `yaml:"password"`
	AuthKeyID        uint16 `yaml:"auth_key_id"`
	KeyImportDomains uint16 `yaml:"key_import_domains"`
}

func (c *Config) id() string {
	return fmt.Sprintf("%s/%d", c.Address, c.AuthKeyID)
}

type hsmKey struct {
	id  uint16
	pub crypt.PublicKey
}

func (h *hsmKey) PublicKey() crypt.PublicKey { return h.pub }
func (h *hsmKey) ID() string                 { return fmt.Sprintf("%04x", h.id) }

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

func parsePublicKey(r *commands.GetPubKeyResponse) (crypt.PublicKey, bool, error) {
	switch r.Algorithm {
	case commands.AlgorithmP256, commands.AlgorithmSecp256k1:
		var curve elliptic.Curve
		switch r.Algorithm {
		case commands.AlgorithmSecp256k1:
			curve = secp256k1.S256()
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
			return nil, false, fmt.Errorf("invalid EC point [%x,%x]", x, y)
		}
		if !curve.IsOnCurve(x, y) {
			return nil, false, fmt.Errorf("invalid EC point [%x,%x]", x, y)
		}

		return &crypt.ECDSAPublicKey{
			Curve: curve,
			X:     x,
			Y:     y,
		}, true, nil

	case commands.AlgorithmED25519:
		if len(r.KeyData) != ed25519.PublicKeySize {
			return nil, false, fmt.Errorf("invalid public key length %d ", len(r.KeyData))
		}
		return crypt.Ed25519PublicKey(r.KeyData), true, nil
	}

	return nil, false, nil
}

func (h *HSM) listObjects(options ...commands.ListCommandOption) ([]commands.Object, error) {
	command, err := commands.CreateListObjectsCommand(options...)
	if err != nil {
		return nil, fmt.Errorf("ListObjects: %w", err)
	}
	res, err := h.session.SendEncryptedCommand(command)
	if err != nil {
		return nil, fmt.Errorf("ListObjects: %w", err)
	}
	listObjectsResponse, ok := res.(*commands.ListObjectsResponse)
	if !ok {
		return nil, fmt.Errorf("unexpected response type: %T", res)
	}
	return listObjectsResponse.Objects, nil
}

// Next implements vault.StoredKeysIterator
func (y *yubihsmStoredKeysIterator) Next() (key vault.StoredKey, err error) {
	if y.objects == nil {
		y.objects, err = y.hsm.listObjects(commands.NewObjectTypeOption(commands.ObjectTypeAsymmetricKey))
		if err != nil {
			return nil, fmt.Errorf("(YubiHSM/%s): %w", y.hsm.conf.id(), err)
		}
	}

	for {
		if y.idx == len(y.objects) {
			return nil, vault.ErrDone
		}

		obj := y.objects[y.idx]
		command, err := commands.CreateGetPubKeyCommand(obj.ObjectID)
		if err != nil {
			return nil, fmt.Errorf("(YubiHSM/%s): GetPubKey: %w", y.hsm.conf.id(), err)
		}
		res, err := y.hsm.session.SendEncryptedCommand(command)
		if err != nil {
			return nil, fmt.Errorf("(YubiHSM/%s): GetPubKey: %w", y.hsm.conf.id(), err)
		}

		pubKeyResponse, ok := res.(*commands.GetPubKeyResponse)
		if !ok {
			return nil, fmt.Errorf("(YubiHSM/%s): unexpected response type: %T", y.hsm.conf.id(), res)
		}
		y.idx++

		pub, ok, err := parsePublicKey(pubKeyResponse)
		if err != nil {
			return nil, fmt.Errorf("(YubiHSM/%s): %w", y.hsm.conf.id(), err)
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
	id, err := strconv.ParseUint(keyID, 16, 16)
	if err != nil {
		return nil, fmt.Errorf("(YubiHSM/%s): %w", h.conf.id(), err)
	}

	command, err := commands.CreateGetPubKeyCommand(uint16(id))
	if err != nil {
		return nil, fmt.Errorf("(YubiHSM/%s): GetPubKey: %w", h.conf.id(), err)
	}
	res, err := h.session.SendEncryptedCommand(command)
	if err != nil {
		return nil, fmt.Errorf("(YubiHSM/%s): GetPubKey: %w", h.conf.id(), err)
	}

	pubKeyResponse, ok := res.(*commands.GetPubKeyResponse)
	if !ok {
		return nil, fmt.Errorf("(YubiHSM/%s): unexpected response type: %T", h.conf.id(), res)
	}

	pub, ok, err := parsePublicKey(pubKeyResponse)
	if err != nil {
		return nil, fmt.Errorf("(YubiHSM/%s): %w", h.conf.id(), err)
	}
	if !ok {
		return nil, fmt.Errorf("(YubiHSM/%s): unsupported key type: %d", h.conf.id(), pubKeyResponse.Algorithm)
	}

	return &hsmKey{
		pub: pub,
		id:  uint16(id),
	}, nil
}

func (h *HSM) signECDSA(digest []byte, id uint16, curve elliptic.Curve) (*crypt.ECDSASignature, error) {
	command, err := commands.CreateSignDataEcdsaCommand(id, digest)
	if err != nil {
		return nil, fmt.Errorf("(YubiHSM/%s): %w", h.conf.id(), err)
	}
	res, err := h.session.SendEncryptedCommand(command)
	if err != nil {
		return nil, fmt.Errorf("(YubiHSM/%s): SignDataEcdsa: %w", h.conf.id(), err)
	}

	ecdsaResponse, ok := res.(*commands.SignDataEcdsaResponse)
	if !ok {
		return nil, fmt.Errorf("(YubiHSM/%s): unexpected response type: %T", h.conf.id(), res)
	}

	var sig struct {
		R *big.Int
		S *big.Int
	}
	if _, err = asn1.Unmarshal(ecdsaResponse.Signature, &sig); err != nil {
		return nil, fmt.Errorf("(YubiHSM/%s): %w", h.conf.id(), err)
	}
	return &crypt.ECDSASignature{
		R:     sig.R,
		S:     sig.S,
		Curve: curve,
	}, nil
}

func (h *HSM) signED25519(digest []byte, id uint16) (crypt.Ed25519Signature, error) {
	command, err := commands.CreateSignDataEddsaCommand(id, digest)
	if err != nil {
		return nil, fmt.Errorf("(YubiHSM/%s): %w", h.conf.id(), err)
	}
	res, err := h.session.SendEncryptedCommand(command)
	if err != nil {
		return nil, fmt.Errorf("(YubiHSM/%s): SignDataEddsa: %w", h.conf.id(), err)
	}

	eddsaResponse, ok := res.(*commands.SignDataEddsaResponse)
	if !ok {
		return nil, fmt.Errorf("(YubiHSM/%s): unexpected response type: %T", h.conf.id(), res)
	}

	if len(eddsaResponse.Signature) != ed25519.SignatureSize {
		return nil, fmt.Errorf("(YubiHSM/%s): invalid ED25519 signature length: %d", h.conf.id(), len(eddsaResponse.Signature))
	}

	return crypt.Ed25519Signature(eddsaResponse.Signature), nil
}

// Sign performs signing operation
func (h *HSM) SignMessage(ctx context.Context, message []byte, k vault.StoredKey) (sig crypt.Signature, err error) {
	digest := crypt.DigestFunc(message)
	key, ok := k.(*hsmKey)
	if !ok {
		return nil, fmt.Errorf("(YubiHSM/%s): not a YubiHSM key: %T", h.conf.id(), k)
	}

	switch k := key.pub.(type) {
	case *crypt.ECDSAPublicKey:
		return h.signECDSA(digest[:], key.id, k.Curve)
	case crypt.Ed25519PublicKey:
		return h.signED25519(digest[:], key.id)
	}

	return nil, fmt.Errorf("(YubiHSM/%s): unexpected key type: %T", h.conf.id(), key.pub)
}

var echoMessage = []byte("health")

// Ready implements vault.ReadinessChecker
func (h *HSM) Ready(ctx context.Context) (bool, error) {
	command, err := commands.CreateEchoCommand(echoMessage)
	if err != nil {
		return false, fmt.Errorf("(YubiHSM/%s): %w", h.conf.id(), err)
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

func getPrivateKeyData(pk crypt.PrivateKey) (typ string, alg commands.Algorithm, caps uint64, p []byte, err error) {
	switch key := pk.(type) {
	case *crypt.ECDSAPrivateKey:
		switch key.Curve {
		case elliptic.P256():
			alg = commands.AlgorithmP256
		case secp256k1.S256():
			alg = commands.AlgorithmSecp256k1
		default:
			return "", 0, 0, nil, fmt.Errorf("unsupported curve: %s", key.Params().Name)
		}
		return strings.ToLower(key.Params().Name), alg, commands.CapabilityAsymmetricSignEcdsa, key.D.Bytes(), nil

	case crypt.Ed25519PrivateKey:
		return "ed25519", commands.AlgorithmED25519, commands.CapabilityAsymmetricSignEddsa, key.Seed(), nil
	}

	return "", 0, 0, nil, fmt.Errorf("unsupported private key type: %T", pk)
}

// Import imports a private key
func (h *HSM) Import(ctx context.Context, pk crypt.PrivateKey, opt utils.Options) (vault.StoredKey, error) {
	typ, alg, caps, p, err := getPrivateKeyData(pk)
	if err != nil {
		return nil, fmt.Errorf("(YubiHSM/%s): %w", h.conf.id(), err)
	}

	domains := h.conf.KeyImportDomains
	d, ok, err := opt.GetInt("domains")
	if err != nil {
		return nil, fmt.Errorf("(YubiHSM/%s): %w", h.conf.id(), err)
	}
	if ok {
		domains = uint16(d)
	}

	label, ok, err := opt.GetString("name")
	if err != nil {
		return nil, fmt.Errorf("(YubiHSM/%s): %w", h.conf.id(), err)
	}
	if !ok {
		label = fmt.Sprintf("signatory-%s-%d", typ, time.Now().Unix())
	}

	command, err := commands.CreatePutAsymmetricKeyCommand(0, []byte(label), domains, caps, alg, p, nil)
	if err != nil {
		return nil, fmt.Errorf("(YubiHSM/%s): %w", h.conf.id(), err)
	}

	res, err := h.session.SendEncryptedCommand(command)
	if err != nil {
		return nil, fmt.Errorf("(YubiHSM/%s): PutAsymmetricKey: %w", h.conf.id(), err)
	}

	keyResponse, ok := res.(*commands.PutAsymmetricKeyResponse)
	if !ok {
		return nil, fmt.Errorf("(YubiHSM/%s): unexpected response type: %T", h.conf.id(), res)
	}

	return &hsmKey{
		id:  keyResponse.KeyID,
		pub: pk.Public(),
	}, nil
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
		v, err := strconv.ParseUint(os.Getenv(envAuthKeyID), 0, 16)
		if err != nil {
			return nil, fmt.Errorf("(YubiHSM): %w", err)
		}
		c.AuthKeyID = uint16(v)
	}

	if c.KeyImportDomains == 0 {
		v, _ := strconv.ParseUint(os.Getenv(envKeyImportDomains), 0, 16)
		c.KeyImportDomains = uint16(v)
	}

	if c.KeyImportDomains == 0 {
		c.KeyImportDomains = defaultDomains
	}

	conn := connector.NewHTTPConnector(config.Address)
	sm, err := yubihsm.NewSessionManager(conn, config.AuthKeyID, config.Password)
	if err != nil {
		return nil, fmt.Errorf("(YubiHSM): %w", err)
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

var _ vault.Importer = &HSM{}
