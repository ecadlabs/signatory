package vault

import (
	"bytes"
	"context"
	"fmt"
	"strconv"

	btcd "github.com/btcsuite/btcd/btcec"
	yubihsm "github.com/certusone/yubihsm-go"
	"github.com/certusone/yubihsm-go/commands"
	"github.com/certusone/yubihsm-go/connector"
	"github.com/ecadlabs/signatory/config"
	"github.com/ecadlabs/signatory/crypto"
	"github.com/ecadlabs/signatory/signatory"
)

// YubiHSM struct containing information required to interrogate a Yubi HSM
type YubiHSM struct {
	sm *yubihsm.SessionManager
}

// YubiKey struct containing information about a Yubi HSM asymmetric-key
type YubiKey struct {
	response *commands.GetPubKeyResponse
	yubiID   uint16
}

// Curve retrieve the curve to be used with this key
func (k *YubiKey) Curve() string {
	if k.response.Algorithm == commands.AlgorithmP256 {
		return crypto.CurveP256
	}
	if k.response.Algorithm == commands.AlgorithmSecp256k1 {
		return crypto.CurveP256K
	}
	if k.response.Algorithm == commands.AlgorighmED25519 {
		return crypto.CurveED25519
	}
	return "unsupported"
}

// ID retrive the id of this key
func (k *YubiKey) ID() string {
	return fmt.Sprintf("%d", k.yubiID)
}

// PublicKey retrive the public key of this key in a compressed format
func (k *YubiKey) PublicKey() []byte {
	if len(k.response.KeyData) > 32 {
		return toCompressedFormat(k.response.KeyData[:32], k.response.KeyData[32:])
	}
	return k.response.KeyData
}

// NewYubi create a NewYubi vault according to config
func NewYubi(config config.YubiConfig) (*YubiHSM, error) {
	c := connector.NewHTTPConnector(config.Host)
	sm, err := yubihsm.NewSessionManager(c, config.AuthKeyID, config.Password)
	if err != nil {
		return nil, err
	}

	return &YubiHSM{sm: sm}, nil
}

// ListPublicKeys list all public key from connected Yubi HSM
func (s *YubiHSM) ListPublicKeys(ctx context.Context) ([]signatory.StoredKey, error) {
	command, err := commands.CreateListObjectsCommand(commands.NewObjectTypeOption(commands.ObjectTypeAsymmetricKey))
	resp, err := s.sm.SendEncryptedCommand(command)
	if err != nil {
		return nil, err
	}

	listObjectsResponse, matched := resp.(*commands.ListObjectsResponse)
	if !matched {
		return nil, fmt.Errorf("Unexpected response type")
	}

	keys := []signatory.StoredKey{}

	for _, object := range listObjectsResponse.Objects {
		command, err := commands.CreateGetPubKeyCommand(object.ObjectID)
		res, err := s.sm.SendEncryptedCommand(command)
		if err != nil {
			return nil, err
		}

		pubKeyResponse, matched := res.(*commands.GetPubKeyResponse)
		if !matched {
			return nil, fmt.Errorf("Unexpected response type")
		}

		keys = append(keys, &YubiKey{
			response: pubKeyResponse,
			yubiID:   object.ObjectID,
		})
	}

	return keys, nil
}

func parseYubiKeyID(value string) (uint16, error) {
	yubiID, err := strconv.ParseUint(value, 10, 16)
	if err != nil {
		return 0, fmt.Errorf("Yubi Key ID need to be 2 bytes")
	}

	return uint16(yubiID), nil
}

// GetPublicKey retrieve a public key from Yubi HSM
func (s *YubiHSM) GetPublicKey(ctx context.Context, keyID string) (signatory.StoredKey, error) {
	yubiID, err := parseYubiKeyID(keyID)
	if err != nil {
		return nil, err
	}

	command, err := commands.CreateGetPubKeyCommand(uint16(yubiID))
	res, err := s.sm.SendEncryptedCommand(command)
	if err != nil {
		return nil, err
	}

	parsedResp, matched := res.(*commands.GetPubKeyResponse)
	if !matched {
		return nil, fmt.Errorf("Unexpected response type")
	}

	return &YubiKey{
		yubiID:   yubiID,
		response: parsedResp,
	}, nil
}

func (s *YubiHSM) signEddsa(yubiID uint16, digest []byte) ([]byte, error) {
	command, err := commands.CreateSignDataEddsaCommand(yubiID, digest)
	if err != nil {
		return nil, err
	}
	res, err := s.sm.SendEncryptedCommand(command)
	if err != nil {
		return nil, err
	}

	parsedResp, matched := res.(*commands.SignDataEddsaResponse)
	if !matched {
		return nil, fmt.Errorf("Unexpected response type")
	}
	return parsedResp.Signature, nil
}

func (s *YubiHSM) signEcdsa(yubiID uint16, digest []byte, storedKey signatory.StoredKey) ([]byte, error) {
	command, err := commands.CreateSignDataEcdsaCommand(uint16(yubiID), digest)
	if err != nil {
		return nil, err
	}

	res, err := s.sm.SendEncryptedCommand(command)
	if err != nil {
		return nil, err
	}

	parsedResp, matched := res.(*commands.SignDataEcdsaResponse)
	if !matched {
		return nil, fmt.Errorf("Unexpected response type")
	}
	signature, err := btcd.ParseDERSignature(parsedResp.Signature, crypto.GetCurve(storedKey.Curve()))
	if err != nil {
		return nil, err
	}
	sig := []byte{}
	sig = append(sig, signature.R.Bytes()...)
	sig = append(sig, signature.S.Bytes()...)
	return sig, nil
}

// Sign produce a signature of digest using the storedKey in YubiHSM
func (s *YubiHSM) Sign(ctx context.Context, digest []byte, storedKey signatory.StoredKey) ([]byte, error) {
	yubiID, err := parseYubiKeyID(storedKey.ID())
	if err != nil {
		return nil, err
	}

	switch storedKey.Curve() {
	case crypto.CurveED25519:
		return s.signEddsa(uint16(yubiID), digest)
	case crypto.CurveP256, crypto.CurveP256K:
		return s.signEcdsa(uint16(yubiID), digest, storedKey)
	default:
		return nil, fmt.Errorf("Unsupported curve for signing %s", storedKey.Curve())
	}
}

// Name return the name of the vault
func (s *YubiHSM) Name() string {
	return "Yubi"
}

// Ready return if the vault is ready
func (s *YubiHSM) Ready() bool {
	echoMessage := []byte("health")

	command, err := commands.CreateEchoCommand(echoMessage)
	if err != nil {
		return false
	}

	resp, err := s.sm.SendEncryptedCommand(command)
	if err != nil {
		return false
	}

	parsedResp, matched := resp.(*commands.EchoResponse)
	if !matched {
		return false
	}

	if bytes.Equal(parsedResp.Data, echoMessage) {
		return true
	} else {
		return false
	}
}
