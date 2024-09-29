package pkcs11

import (
	"context"
	"encoding/hex"
	stderr "errors"
	"fmt"
	"net/http"
	"os"
	"strconv"

	"github.com/ecadlabs/go-pkcs11/pkcs11"
	"github.com/ecadlabs/gotez/v2/crypt"
	"github.com/ecadlabs/signatory/pkg/errors"
	"github.com/ecadlabs/signatory/pkg/vault"
	"github.com/ecadlabs/signatory/pkg/vault/memory"
	"gopkg.in/yaml.v3"
)

type PKCS11Vault struct {
	module *pkcs11.Module
	slot   *pkcs11.Slot
	info   pkcs11.Info
	conf   Config
}

type Config struct {
	LibraryPath string `yaml:"library_path"`
	Pin         string `yaml:"pin"`
	Slot        uint   `yaml:"slot"`
	Label       string `yaml:"label"`
	ObjectID    string `yaml:"object_id"`
}

type iterElem struct {
	obj *pkcs11.Object
	v   *PKCS11Vault
}

func (i *iterElem) Elem() (vault.StoredKey, error) {
	pk, err := i.obj.PrivateKey()
	if err != nil {
		return nil, i.v.formatError(err)
	}
	kp, err := pk.KeyPair()
	if err != nil {
		return nil, i.v.formatError(err)
	}
	key := &keyPair{
		obj: i.obj,
		kp:  kp,
	}
	return key, nil
}

type keyPair struct {
	obj *pkcs11.Object
	kp  pkcs11.KeyPair
}

func (p *keyPair) ID() string {
	return fmt.Sprintf("%08x", p.obj.Handle())
}

func (p *keyPair) PublicKey() crypt.PublicKey {
	pub, err := crypt.NewPublicKeyFrom(p.kp.Public())
	if err != nil {
		panic(err) // shouldn't happen
	}
	return pub
}

func (v *PKCS11Vault) formatError(err error) error {
	return fmt.Errorf("(PKCS#11/%s %d.%d): %w", v.info.Manufacturer, v.info.Version.Major, v.info.Version.Minor, err)
}

const (
	envLibraryPath = "PKCS11_PATH"
	envPin         = "PKCS11_PIN"
	envSlot        = "PKCS11_SLOT"
	envLabel       = "PKCS11_LABEL"
	envObjID       = "PKCS11_OBJECT_ID"
)

func New(ctx context.Context, config *Config) (*PKCS11Vault, error) {
	conf := *config
	if conf.LibraryPath == "" {
		conf.LibraryPath = os.Getenv(envLibraryPath)
	}
	if conf.Pin == "" {
		conf.Pin = os.Getenv(envPin)
	}
	if conf.Label == "" {
		conf.Label = os.Getenv(envLabel)
	}
	if conf.ObjectID == "" {
		conf.ObjectID = os.Getenv(envObjID)
	}

	module, err := pkcs11.Open(config.LibraryPath)
	if err != nil {
		return nil, fmt.Errorf("(PKCS#11/%s): %w", config.LibraryPath, err)
	}
	v := PKCS11Vault{
		module: module,
		info:   module.Info(),
		conf:   conf,
	}
	return &v, nil
}

type errIterator struct {
	err error
}

func (e errIterator) Next() (vault.StoredKey, error) {
	return nil, e.err
}

// GetPublicKey returns a public key by given ID
func (v *PKCS11Vault) ListPublicKeys(ctx context.Context) vault.StoredKeysIterator {
	if v.slot == nil {
		return errIterator{v.formatError(errors.New("locked"))}
	}

	filter := []pkcs11.Filter{
		pkcs11.FilterClass(pkcs11.ClassPrivateKey),
		pkcs11.FilterKeyType(pkcs11.KeyTypeEC),
	}
	if v.conf.Label != "" {
		filter = append(filter, pkcs11.FilterLabel(v.conf.Label))
	}
	if v.conf.ObjectID != "" {
		id, err := hex.DecodeString(v.conf.ObjectID)
		if err != nil {
			return errIterator{v.formatError(err)}
		}
		filter = append(filter, pkcs11.FilterID(id))
	}

	objects, err := v.slot.Objects(filter...)
	if err != nil {
		return errIterator{v.formatError(err)}
	}

	elems := make([]*iterElem, len(objects))
	for i, o := range objects {
		elems[i] = &iterElem{
			obj: o,
			v:   v,
		}
	}
	return memory.NewIterator(elems)
}

func (v *PKCS11Vault) GetPublicKey(ctx context.Context, id string) (vault.StoredKey, error) {
	if v.slot == nil {
		return nil, v.formatError(errors.New("locked"))
	}
	handle, err := strconv.ParseUint(id, 16, 64)
	if err != nil {
		return nil, v.formatError(err)
	}
	obj, err := v.slot.NewObject(uint(handle))
	if err != nil {
		if stderr.Is(err, pkcs11.ErrObjectHandleInvalid) {
			return nil, errors.Wrap(v.formatError(err), http.StatusNotFound)
		}
		return nil, v.formatError(err)
	}
	pk, err := obj.PrivateKey()
	if err != nil {
		return nil, v.formatError(err)
	}
	kp, err := pk.KeyPair()
	if err != nil {
		return nil, v.formatError(err)
	}
	key := &keyPair{
		obj: obj,
		kp:  kp,
	}
	return key, nil
}

func (v *PKCS11Vault) SignMessage(ctx context.Context, msg []byte, key vault.StoredKey) (crypt.Signature, error) {
	if v.slot == nil {
		return nil, v.formatError(errors.New("locked"))
	}
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

func (v *PKCS11Vault) Unlock(ctx context.Context) error {
	slot, err := v.module.Slot(v.conf.Slot, pkcs11.OptUserPIN(v.conf.Pin))
	if err != nil {
		return v.formatError(err)
	}
	v.slot = slot
	return nil
}

func (c *PKCS11Vault) Name() string {
	return "PKCS#11"
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
		return New(ctx, &conf)
	})
}
