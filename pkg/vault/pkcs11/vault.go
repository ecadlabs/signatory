package pkcs11

import (
	"context"
	"encoding/hex"
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
	envSlot        = "PKCS11_SLOT"
	envPin         = "PKCS11_PIN"
)

type KeyConfig struct {
	Label string `yaml:"label"`
	ID    string `yaml:"id"`
}

type KeyPair struct {
	Private         *KeyConfig      `yaml:"private"`
	ExtendedPrivate bool            `yaml:"extended_private"` // Specific to AWS CloudHSM: set to true if the private key has a public key value as an attribute
	Public          *KeyConfig      `yaml:"public"`
	PublicValue     gotez.PublicKey `yaml:"public_value"`
}

type Config struct {
	LibraryPath             string                   `yaml:"library_path"`
	Slot                    *uint                    `yaml:"slot"` // Find the first slot with initialized token if empty
	Pin                     string                   `yaml:"pin"`
	Keys                    []*KeyPair               `yaml:"keys"` // Use all available keys if nil
	PublicKeysSearchOptions *PublicKeysSearchOptions `yaml:"public_keys_search_options"`
}

type PublicKeysSearchOptions struct {
	MatchLabel      bool `yaml:"match_label"`
	MatchID         bool `yaml:"match_id"`
	ExtendedPrivate bool `yaml:"extended_private"` // Specific to AWS CloudHSM: set to true if the private key has a public key value as an attribute
}

func (o *PublicKeysSearchOptions) flags() (flags pkcs11.MatchFlags) {
	if o.MatchLabel {
		flags |= pkcs11.MatchLabel
	}
	if o.MatchID {
		flags |= pkcs11.MatchID
	}
	if o.ExtendedPrivate {
		flags |= pkcs11.ExtendedPrivate
	}
	return
}

func (c *Config) searchOptions() *PublicKeysSearchOptions {
	if c.PublicKeysSearchOptions != nil {
		return c.PublicKeysSearchOptions
	}
	return &PublicKeysSearchOptions{MatchLabel: true, MatchID: true, ExtendedPrivate: true}
}

type keyPair struct {
	kp pkcs11.KeyPair
	v  *PKCS11Vault
}

func (p *keyPair) PublicKey() crypt.PublicKey {
	pub, err := crypt.NewPublicKeyFrom(p.kp.Public())
	if err != nil {
		panic(err) // shouldn't happen
	}
	return pub
}

func (p *keyPair) Vault() vault.Vault { return p.v }

func (kp *keyPair) Sign(ctx context.Context, msg []byte) (crypt.Signature, error) {
	digest := crypt.DigestFunc(msg)
	sig, err := kp.kp.Sign(nil, digest[:], nil)
	if err != nil {
		return nil, kp.v.formatError(err)
	}
	ret, err := crypt.NewSignatureFromBytes(sig, kp.PublicKey())
	if err != nil {
		return nil, kp.v.formatError(err)
	}
	return ret, nil
}

type PKCS11Vault struct {
	mod     *pkcs11.Module
	session *pkcs11.Session
	keys    []pkcs11.KeyPair
	conf    *Config
}

func (v *PKCS11Vault) formatError(err error) error {
	return formatError(v.mod, err)
}

// GetPublicKey returns a public key by given ID
func (v *PKCS11Vault) List(ctx context.Context) vault.KeyIterator {
	i := 0
	return vault.IteratorFunc(func() (key vault.KeyReference, err error) {
		if i >= len(v.keys) {
			return nil, vault.ErrDone
		}
		kp := &keyPair{
			kp: v.keys[i],
			v:  v,
		}
		i++
		return kp, nil
	})
}

func (c *PKCS11Vault) Name() string {
	return fmt.Sprintf("PKCS#11/%s %v", c.mod.Info().Manufacturer, c.mod.Info().Version)
}

func formatError(mod *pkcs11.Module, err error) error {
	return fmt.Errorf("(PKCS#11/%s %v): %w", mod.Info().Manufacturer, mod.Info().Version, err)
}

func findSlot(mod *pkcs11.Module) (uint, error) {
	// use first slot with a token
	slots, err := mod.SlotIDs()
	if err != nil {
		return 0, formatError(mod, err)
	}
	for _, s := range slots {
		si, err := mod.SlotInfo(s)
		if err != nil {
			return 0, formatError(mod, err)
		}

		if si.Token != nil && si.Token.Flags&pkcs11.TokenTokenInitialized != 0 {
			return s, nil
		}
	}
	return 0, formatError(mod, errors.New("token not found"))
}

func (v *PKCS11Vault) getKeyObject(conf *KeyConfig, class pkcs11.Class) (*pkcs11.Object, error) {
	// find by label or id
	filter := []pkcs11.Value{pkcs11.NewScalarV(pkcs11.AttributeClass, class)}
	if conf.Label != "" {
		filter = append(filter, pkcs11.NewString(pkcs11.AttributeLabel, conf.Label))
	}
	if conf.ID != "" {
		id, err := hex.DecodeString(conf.ID)
		if err != nil {
			return nil, err
		}
		filter = append(filter, pkcs11.NewBytes(pkcs11.AttributeID, id))
	}

	objects, err := v.session.Objects(filter...)
	if err != nil {
		return nil, v.formatError(err)
	}
	if len(objects) == 0 {
		return nil, errors.Wrap(v.formatError(fmt.Errorf("key is not found: %#v", conf)), http.StatusNotFound)
	}
	if len(objects) != 1 {
		return nil, v.formatError(fmt.Errorf("non-unique key: %v", conf))
	}
	return objects[0], nil
}

func (v *PKCS11Vault) initStatic() error {
	for _, kpConf := range v.conf.Keys {
		privObj, err := v.getKeyObject(kpConf.Private, pkcs11.ClassPrivateKey)
		if err != nil {
			return err
		}

		priv, err := privObj.PrivateKey()
		if err != nil {
			return v.formatError(err)
		}

		var kp pkcs11.KeyPair
		if kpConf.PublicValue != nil {
			p, err := crypt.NewPublicKey(kpConf.PublicValue)
			if err != nil {
				return v.formatError(err)
			}
			kp, err = priv.AddPublic(p.Unwrap())
			if err != nil {
				return v.formatError(err)
			}
			log.WithField("handle", fmt.Sprintf("%#016x", priv.Handle())).Debug("Private key object")
		} else if kpConf.ExtendedPrivate {
			// CloudHSM case
			var err error
			kp, err = priv.KeyPair(pkcs11.ExtendedPrivate)
			if err != nil {
				return v.formatError(err)
			}
			log.WithField("handle", fmt.Sprintf("%#016x", priv.Handle())).Debug("Extended private key object")
		} else {
			pubConf := kpConf.Public
			if pubConf == nil {
				pubConf = kpConf.Private
			}

			pubObj, err := v.getKeyObject(pubConf, pkcs11.ClassPublicKey)
			if err != nil {
				return err
			}
			pub, err := pubObj.PublicKey()
			if err != nil {
				return v.formatError(err)
			}
			kp, err = priv.AddPublic(pub)
			if err != nil {
				return v.formatError(err)
			}
			log.WithFields(log.Fields{
				"private_handle": fmt.Sprintf("%#016x", priv.Handle()),
				"public_handle":  fmt.Sprintf("%#016x", pubObj.Handle()),
			}).Debug("Key pair")
		}
		v.keys = append(v.keys, kp)
	}
	return nil
}

func (v *PKCS11Vault) enumKeys() error {
	filter := []pkcs11.Value{pkcs11.NewScalarV(pkcs11.AttributeClass, pkcs11.ClassPrivateKey)}
	objects, err := v.session.Objects(filter...)
	if err != nil {
		return v.formatError(err)
	}

	searchOpt := v.conf.searchOptions()
	for _, obj := range objects {
		priv, err := obj.PrivateKey()
		if err != nil {
			log.WithField("handle", obj.Handle()).Error(err)
			continue
		}
		kp, err := priv.KeyPair(searchOpt.flags())
		if err != nil {
			log.WithField("handle", obj.Handle()).Error(err)
			continue
		}
		log.WithFields(log.Fields{
			"private_handle": fmt.Sprintf("%#016x", priv.Handle()),
		}).Debug("Key pair discovered")
		v.keys = append(v.keys, kp)
	}
	return nil
}

func (v *PKCS11Vault) initKeys() error {
	if v.conf.Keys != nil {
		return v.initStatic()
	}
	return v.enumKeys()
}

func New(config *Config) (*PKCS11Vault, error) {
	lib := config.LibraryPath
	if lib == "" {
		lib = os.Getenv(envLibraryPath)
	}

	mod, err := pkcs11.Open(lib, pkcs11.OptOsLockingOk)
	if err != nil {
		return nil, fmt.Errorf("(PKCS#11/%s): %w", path.Base(lib), err)
	}
	log.Debug(mod.Info())

	var slot uint
	if config.Slot != nil {
		slot = *config.Slot
	} else if s := os.Getenv(envSlot); s != "" {
		v, err := strconv.ParseUint(s, 0, 64)
		if err != nil {
			return nil, formatError(mod, err)
		}
		if v > uint64(^uint(0)) {
			return nil, fmt.Errorf("(PKCS#11/%s): slot value exceeds maximum uint size", path.Base(lib))
		}
		slot = uint(v)
	} else if slot, err = findSlot(mod); err != nil {
		return nil, err
	}

	pin := config.Pin
	if pin == "" {
		pin = os.Getenv(envPin)
	}

	session, err := mod.NewSession(slot, pkcs11.OptUserPIN(pin))
	if err != nil {
		return nil, formatError(mod, err)
	}

	v := PKCS11Vault{
		mod:     mod,
		session: session,
		conf:    config,
		keys:    make([]pkcs11.KeyPair, 0),
	}
	return &v, v.initKeys()
}

func (v *PKCS11Vault) Close(context.Context) error {
	if err := v.session.Close(); err != nil {
		return err
	}
	return v.mod.Close()
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

var _ vault.Vault = (*PKCS11Vault)(nil)
