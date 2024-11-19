package pkcs11

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path"
	"strconv"

	"github.com/ecadlabs/go-pkcs11/pkcs11"
	"github.com/ecadlabs/gotez/v2"
	"github.com/ecadlabs/gotez/v2/crypt"
	"github.com/ecadlabs/signatory/pkg/errors"
	"github.com/ecadlabs/signatory/pkg/vault"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
)

const (
	envLibraryPath = "PKCS11_PATH"
)

func envPin(slot uint) string {
	return fmt.Sprintf("PKCS11_SLOT%d_PIN", slot)
}

type PKCS11Vault struct {
	module   Module
	sessions map[uint]*pkcs11.Session
	conf     Config
}

type KeyConfig struct {
	Label    string `yaml:"label" json:"label,omitempty"`
	ObjectID string `yaml:"object_id" json:"object_id,omitempty"`
}

type KeyPair struct {
	Slot        uint            `yaml:"slot"`
	Private     *KeyConfig      `yaml:"private"`
	Public      *KeyConfig      `yaml:"public"`
	PublicValue gotez.PublicKey `yaml:"public_value"`
}

type Config struct {
	LibraryPath string           `yaml:"library_path"`
	Slots       map[uint]*string `yaml:"slots"`
	Keys        []*KeyPair       `yaml:"keys"`
}

type keyPair struct {
	idx int
	kp  pkcs11.KeyPair
}

func (p *keyPair) ID() string {
	return strconv.FormatInt(int64(p.idx), 10)
}

func (p *keyPair) PublicKey() crypt.PublicKey {
	pub, err := crypt.NewPublicKeyFrom(p.kp.Public())
	if err != nil {
		panic(err) // shouldn't happen
	}
	return pub
}

var testDigest = sha256.Sum256([]byte("test"))

// check if the pair is valid
func (p *keyPair) validate() error {
	sig, err := p.kp.Sign(rand.Reader, testDigest[:], nil)
	if err != nil {
		return err
	}
	var ok bool
	switch pub := p.kp.Public().(type) {
	case ed25519.PublicKey:
		ok = ed25519.Verify(pub, testDigest[:], sig)
	case *ecdsa.PublicKey:
		ok = ecdsa.VerifyASN1(pub, testDigest[:], sig)
	default:
		return fmt.Errorf("unexpected key type %T", pub)
	}
	if !ok {
		return errors.New("key pair validation failed")
	}
	return nil
}

func (v *PKCS11Vault) formatError(err error) error {
	return v.module.formatError(err)
}

type iterator struct {
	v   *PKCS11Vault
	idx int
}

func (it *iterator) Next() (vault.StoredKey, error) {
	if it.idx == len(it.v.conf.Keys) {
		return nil, vault.ErrDone
	}
	keyPairConf := it.v.conf.Keys[it.idx]
	i := it.idx
	it.idx++

	kp, err := it.v.getKeyPair(keyPairConf)
	if err != nil {
		return nil, err
	}
	kp.idx = i
	return kp, nil
}

func (v *PKCS11Vault) getKeyPair(k *KeyPair) (*keyPair, error) {
	privObj, err := v.getKeyObj(k.Slot, k.Private, pkcs11.ClassPrivateKey)
	if err != nil {
		return nil, err
	}

	priv, err := privObj.PrivateKey()
	if err != nil {
		return nil, v.formatError(err)
	}

	var pub crypto.PublicKey
	if k.PublicValue != nil {
		p, err := crypt.NewPublicKey(k.PublicValue)
		if err != nil {
			return nil, v.formatError(err)
		}
		pub = p.Unwrap()
	} else {
		pubConf := k.Public
		if pubConf == nil {
			pubConf = k.Private
		}

		pubObj, err := v.getKeyObj(k.Slot, pubConf, pkcs11.ClassPublicKey)
		if err != nil {
			return nil, err
		}
		if pub, err = pubObj.PublicKey(); err != nil {
			return nil, v.formatError(err)
		}
	}

	kp, err := priv.AddPublic(pub)
	if err != nil {
		return nil, v.formatError(err)
	}
	out := keyPair{
		kp: kp,
	}
	if err := out.validate(); err != nil {
		return nil, v.formatError(err)
	}
	return &out, nil
}

func ignoreError[X any](v X, _ error) X {
	return v
}

func (v *PKCS11Vault) getKeyObj(slot uint, c *KeyConfig, class pkcs11.Class) (*pkcs11.Object, error) {
	session, ok := v.sessions[slot]
	if !ok {
		return nil, v.formatError(fmt.Errorf("slot %d is not configured", slot))
	}

	// find by label or id
	filter := []pkcs11.Filter{
		pkcs11.FilterClass(class),
	}
	if c != nil {
		if c.Label != "" {
			filter = append(filter, pkcs11.FilterLabel(c.Label))
		}
		if c.ObjectID != "" {
			id, err := hex.DecodeString(c.ObjectID)
			if err != nil {
				return nil, err
			}
			filter = append(filter, pkcs11.FilterID(id))
		}
	}

	objects, err := session.Objects(filter...)
	if err != nil {
		return nil, v.formatError(err)
	}
	if len(objects) == 0 {
		return nil, errors.Wrap(v.formatError(fmt.Errorf("key is not found: %s", string(ignoreError(json.Marshal(c))))), http.StatusNotFound)
	}
	if len(objects) != 1 {
		return nil, v.formatError(fmt.Errorf("non-unique key: %s", string(ignoreError(json.Marshal(c)))))
	}
	return objects[0], nil
}

// GetPublicKey returns a public key by given ID
func (v *PKCS11Vault) ListPublicKeys(ctx context.Context) vault.StoredKeysIterator {
	return &iterator{v: v}
}

func (v *PKCS11Vault) GetPublicKey(ctx context.Context, id string) (vault.StoredKey, error) {
	idx, err := strconv.ParseInt(id, 16, 32)
	if err != nil {
		return nil, v.formatError(err)
	}
	if int(idx) >= len(v.conf.Keys) {
		return nil, errors.Wrap(v.formatError(errors.New("index is out of range")), http.StatusNotFound)

	}
	kp, err := v.getKeyPair(v.conf.Keys[idx])
	if err != nil {
		return nil, err
	}
	kp.idx = int(idx)
	return kp, nil
}

func (v *PKCS11Vault) SignMessage(ctx context.Context, msg []byte, key vault.StoredKey) (crypt.Signature, error) {
	kp, ok := key.(*keyPair)
	if !ok {
		return nil, v.formatError(fmt.Errorf("invalid key type %T", key))
	}
	digest := crypt.DigestFunc(msg)
	sig, err := kp.kp.Sign(nil, digest[:], nil)
	if err != nil {
		return nil, v.formatError(err)
	}
	ret, err := crypt.NewSignatureFromBytes(sig, kp.PublicKey())
	if err != nil {
		return nil, v.formatError(err)
	}
	return ret, nil
}

func (c *PKCS11Vault) Name() string {
	return "PKCS#11"
}

func (c *PKCS11Vault) VaultName() string {
	return fmt.Sprintf("%s %v", c.module.info.Manufacturer, c.module.info.Version)
}

type Module struct {
	mod  *pkcs11.Module
	info *pkcs11.ModuleInfo
}

func (m Module) formatError(err error) error {
	return fmt.Errorf("(PKCS#11/%s %v): %w", m.info.Manufacturer, m.info.Version, err)
}

func (m Module) Close() error {
	return m.mod.Close()
}

func Open(p string) (Module, error) {
	if p == "" {
		p = os.Getenv(envLibraryPath)
	}
	mod, err := pkcs11.Open(p)
	if err != nil {
		return Module{}, fmt.Errorf("(PKCS#11/%s): %w", path.Base(p), err)
	}
	log.Debug(mod.Info())
	return Module{
		mod:  mod,
		info: mod.Info(),
	}, nil
}

func (m Module) FindSlot() (uint, error) {
	// use first slot with a token
	slots, err := m.mod.SlotIDs()
	if err != nil {
		return 0, m.formatError(err)
	}
	for _, s := range slots {
		si, err := m.mod.SlotInfo(s)
		if err != nil {
			return 0, m.formatError(err)
		}
		if si.Token != nil {
			return s, nil
		}
	}
	return 0, m.formatError(errors.New("token not found"))
}

func NewWithModule(mod Module, config *Config) (*PKCS11Vault, error) {
	v := PKCS11Vault{
		module:   mod,
		sessions: make(map[uint]*pkcs11.Session),
		conf:     *config,
	}

	for s, pin := range config.Slots {
		if pin == nil {
			p := os.Getenv(envPin(s))
			pin = &p
		}
		session, err := v.module.mod.NewSession(s, pkcs11.OptUserPIN(*pin))
		if err != nil {
			return nil, v.formatError(err)
		}
		v.sessions[s] = session

		if log.GetLevel() >= log.DebugLevel {
			filter := []pkcs11.Filter{}
			objects, err := session.Objects(filter...)
			if err != nil {
				return nil, v.formatError(err)
			}
			for _, obj := range objects {
				l := log.WithFields(log.Fields{"slot": s, "class": obj.Class(), "handle": fmt.Sprintf("%#016x", obj.Handle())})
				if id := obj.ID(); id != nil {
					l = l.WithField("id", hex.EncodeToString(id))
				}
				l.Debug("object found")
			}
		}
	}
	return &v, nil
}

func New(config *Config) (*PKCS11Vault, error) {
	mod, err := Open(config.LibraryPath)
	if err != nil {
		return nil, err
	}
	return NewWithModule(mod, config)
}

func (v *PKCS11Vault) Close() error {
	for _, s := range v.sessions {
		if err := s.Close(); err != nil {
			return err
		}
	}
	return v.module.Close()
}

func init() {
	vault.RegisterVault("pkcs11", func(ctx context.Context, node *yaml.Node) (vault.Vault, error) {
		var conf Config
		if node == nil {
			return nil, errors.New("(PKCS#11): config is missing")
		}
		if err := node.Decode(&conf); err != nil {
			return nil, err
		}
		return New(&conf)
	})
}

var _ vault.VaultNamer = (*PKCS11Vault)(nil)
