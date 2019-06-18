package vault

import (
	"bytes"
	"fmt"
	"strconv"

	btcd "github.com/btcsuite/btcd/btcec"
	yubihsm "github.com/certusone/yubihsm-go"
	"github.com/certusone/yubihsm-go/commands"
	"github.com/certusone/yubihsm-go/connector"
	"github.com/ecadlabs/signatory/config"
	"github.com/ecadlabs/signatory/crypto"
	"github.com/ecadlabs/signatory/signatory"
	log "github.com/sirupsen/logrus"
)

// YubiHSM struct containing information required to interogate a Yubi HSM
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
	return "unsupported"
}

// ID retrive the id of this key
func (k *YubiKey) ID() string {
	return fmt.Sprintf("%d", k.yubiID)
}

// PublicKey retrive the public key of this key in a compressed format
func (k *YubiKey) PublicKey() []byte {
	return toCompressedFormat(k.response.KeyData[:32], k.response.KeyData[32:])
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
func (s *YubiHSM) ListPublicKeys() ([]signatory.StoredKey, error) {
	command, err := commands.CreateListObjectsCommand(commands.NewObjectTypeOption(commands.ObjectTypeAsymmetricKey))
	resp, err := s.sm.SendEncryptedCommand(command)
	if err != nil {
		return nil, err
	}

	listObjectsReponse, matched := resp.(*commands.ListObjectsResponse)
	if !matched {
		return nil, fmt.Errorf("Unexpected response type")
	}

	keys := []signatory.StoredKey{}

	for _, object := range listObjectsReponse.Objects {
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
func (s *YubiHSM) GetPublicKey(keyID string) (signatory.StoredKey, error) {
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

// Sign produce a signature of digest using the storedKey in YubiHSM
func (s *YubiHSM) Sign(digest []byte, storedKey signatory.StoredKey) ([]byte, error) {
	log.Infof("Signing operation with Yubi HSM")
	yubiID, err := parseYubiKeyID(storedKey.ID())
	if err != nil {
		return nil, err
	}

	command, err := commands.CreateSignDataEcdsaCommand(uint16(yubiID), digest)
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
