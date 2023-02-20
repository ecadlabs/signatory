package signatory

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	stderr "errors"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"

	"github.com/ecadlabs/signatory/pkg/auth"
	"github.com/ecadlabs/signatory/pkg/config"
	"github.com/ecadlabs/signatory/pkg/cryptoutils"
	"github.com/ecadlabs/signatory/pkg/errors"
	"github.com/ecadlabs/signatory/pkg/tezos"
	"github.com/ecadlabs/signatory/pkg/vault"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
)

var (
	// ErrVaultNotFound error return when a vault is not found
	ErrVaultNotFound = errors.Wrap(stderr.New("this key not found in any vault"), http.StatusNotFound)
	// ErrNotSafeToSign error returned when an operation is a potential duplicate
	ErrNotSafeToSign = errors.Wrap(stderr.New("not safe to sign"), http.StatusForbidden)
)

const (
	logPKH       = "pkh"
	logVault     = "vault"
	logVaultName = "vault_name"
	logReq       = "request"
	logOps       = "ops"
	logTotalOps  = "ops_total"
	logKeyID     = "key_id"
	logChainID   = "chain_id"
	logLevel     = "lvl"
	logClient    = "client_pkh"
	logRaw       = "raw"
)

// SignInterceptor is an observer function for signing request
type SignInterceptor func(opt *SignInterceptorOptions, sing func() error) error

// SignInterceptorOptions contains SignInterceptor arguments to avoid confusion
type SignInterceptorOptions struct {
	Address string
	Vault   string
	Req     string
	Stat    tezos.OperationsStat
}

// Policy contains policy data related to the key
type Policy struct {
	AllowedRequests     []string
	AllowedOps          []string
	LogPayloads         bool
	AuthorizedKeyHashes []string
}

// PublicKey contains base58 encoded public key with its hash
type PublicKey struct {
	PublicKey     string
	PublicKeyHash string
	VaultName     string
	ID            string
	Policy        *Policy
	Active        bool
}

// Signatory is a struct coordinate signatory action and select vault according to the key being used
type Signatory struct {
	config Config
	vaults map[string]vault.Vault
	cache  keyCache
}

// SignRequest represents a sign request which may be authenticated with the client key
type SignRequest struct {
	ClientPublicKeyHash string // optional, see policy
	PublicKeyHash       string
	Source              net.IP // optional caller address
	Message             []byte
}

type keyVaultPair struct {
	pkh   string
	key   vault.StoredKey
	vault vault.Vault
	name  string
}

type keyCache struct {
	cache map[string]*keyVaultPair
	mtx   sync.Mutex
}

func (k *keyCache) push(pkh string, pair *keyVaultPair) {
	k.mtx.Lock()
	defer k.mtx.Unlock()

	if k.cache == nil {
		k.cache = make(map[string]*keyVaultPair)
	}
	k.cache[pkh] = pair
}

func (k *keyCache) get(pkh string) *keyVaultPair {
	k.mtx.Lock()
	defer k.mtx.Unlock()

	if pair, ok := k.cache[pkh]; ok {
		return pair
	}

	return nil
}

func (k *keyCache) drop() {
	k.mtx.Lock()
	defer k.mtx.Unlock()
	k.cache = nil
}

func (s *Signatory) logger() log.FieldLogger {
	if s.config.Logger != nil {
		return s.config.Logger
	}
	return log.StandardLogger()
}

var defaultPolicy = Policy{
	AllowedRequests: []string{"block", "preendorsement", "endorsement"},
}

func (s *Signatory) fetchPolicyOrDefault(keyHash string) *Policy {
	val, ok := s.config.Policy[keyHash]
	if !ok {
		return nil
	}
	if val != nil {
		return val
	}
	return &defaultPolicy
}

func matchFilter(policy *Policy, req *SignRequest, msg tezos.UnsignedMessage) error {
	if policy.AuthorizedKeyHashes != nil {
		if req.ClientPublicKeyHash == "" {
			return errors.New("authentication required")
		}

		var allowed bool
		for _, k := range policy.AuthorizedKeyHashes {
			if k == req.ClientPublicKeyHash {
				allowed = true
				break
			}
		}

		if !allowed {
			return fmt.Errorf("client `%s' is not allowed", req.ClientPublicKeyHash)
		}
	}

	kind := msg.MessageKind()
	var allowed bool
	for _, k := range policy.AllowedRequests {
		if kind == k {
			allowed = true
			break
		}
	}

	if !allowed {
		return fmt.Errorf("request kind `%s' is not allowed", kind)
	}

	if ops, ok := msg.(*tezos.GenericOperationRequest); ok {
		for _, op := range ops.Contents {
			kind := op.OperationKind()
			allowed = false
			for _, k := range policy.AllowedOps {
				if kind == k {
					allowed = true
					break
				}
			}
			if !allowed {
				return fmt.Errorf("operation `%s' is not allowed", kind)
			}
		}
	}
	return nil
}

func (s *Signatory) callPolicyHook(ctx context.Context, req *SignRequest) error {
	if s.config.PolicyHook == nil {
		return nil
	}
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}

	hookReq := PolicyHookRequest{
		Request:       req.Message,
		Source:        req.Source,
		PublicKeyHash: req.PublicKeyHash,
		ClientKeyHash: req.ClientPublicKeyHash,
		Nonce:         nonce[:],
	}
	body, err := json.Marshal(&hookReq)
	if err != nil {
		return err
	}
	r, err := http.NewRequestWithContext(ctx, "POST", s.config.PolicyHook.Address, bytes.NewReader(body))
	if err != nil {
		return err
	}
	r.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(r)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if s.config.PolicyHook.Auth != nil {
		// authenticate the responce
		var reply PolicyHookReply
		if err := json.NewDecoder(resp.Body).Decode(&reply); err != nil {
			return err
		}
		var pl PolicyHookReplyPayload
		if err := json.Unmarshal(reply.Payload, &pl); err != nil {
			return err
		}
		if pl.Status != resp.StatusCode {
			return stderr.New("the policy hook reply status must match the HTTP header")
		}
		if !bytes.Equal(pl.Nonce, hookReq.Nonce) {
			return errors.Wrap(errors.New("nonce mismatch"), http.StatusForbidden)
		}
		pub, err := s.config.PolicyHook.Auth.GetPublicKey(ctx, pl.PublicKeyHash)
		if err != nil {
			errors.Wrap(err, http.StatusForbidden)
		}
		sig, err := tezos.ParseSignature(reply.Signature, pub)
		if err != nil {
			return err
		}
		if err = cryptoutils.Verify(pub, reply.Payload, sig); err != nil {
			if stderr.Is(err, cryptoutils.ErrSignature) {
				return errors.Wrap(errors.New("invalid hook reply signature"), http.StatusForbidden)
			}
			return err
		}
		if resp.StatusCode/100 != 2 {
			var msg string
			if pl.Error != "" {
				msg = pl.Error
			} else {
				msg = resp.Status
			}
			var status int
			if resp.StatusCode/100 == 4 {
				status = http.StatusForbidden
			} else {
				status = http.StatusInternalServerError
			}
			return errors.Wrap(fmt.Errorf("policy hook: %s", msg), status)
		}
	} else if resp.StatusCode/100 != 2 {
		var status int
		if resp.StatusCode/100 == 4 {
			status = http.StatusForbidden
		} else {
			status = http.StatusInternalServerError
		}
		return errors.Wrap(fmt.Errorf("policy hook: %s", resp.Status), status)
	}

	return nil
}

// Sign ask the vault to sign a message with the private key associated to keyHash
func (s *Signatory) Sign(ctx context.Context, req *SignRequest) (string, error) {
	l := s.logger().WithField(logPKH, req.PublicKeyHash)

	if req.ClientPublicKeyHash != "" {
		l = l.WithField(logClient, req.ClientPublicKeyHash)
	}

	policy := s.fetchPolicyOrDefault(req.PublicKeyHash)
	if policy == nil {
		err := fmt.Errorf("%s is not listed in config", strings.Replace(req.PublicKeyHash, "\n", "", -1))
		l.WithField(logRaw, hex.EncodeToString(req.Message)).Error(err)
		return "", errors.Wrap(err, http.StatusForbidden)
	}

	msg, err := tezos.ParseRequest(req.Message)
	if err != nil {
		l.WithField(logRaw, hex.EncodeToString(req.Message)).Error(strings.Replace(err.Error(), "\n", "", -1))
		return "", errors.Wrap(err, http.StatusBadRequest)
	}

	l = l.WithField(logReq, msg.MessageKind())

	if m, ok := msg.(tezos.MessageWithLevel); ok {
		l = l.WithFields(log.Fields{logChainID: m.GetChainID(), logLevel: m.GetLevel()})
	}

	var opStat tezos.OperationsStat
	if ops, ok := msg.(*tezos.GenericOperationRequest); ok {
		opStat = ops.OperationsStat()
		l = l.WithFields(log.Fields{logOps: opStat, logTotalOps: len(ops.Contents)})
	}

	p, err := s.getPublicKey(ctx, req.PublicKeyHash)
	if err != nil {
		l.Error(err)
		return "", err
	}

	l = l.WithField(logVault, p.vault.Name())
	if n, ok := p.vault.(vault.VaultNamer); ok {
		l = l.WithField(logVaultName, n.VaultName())
	} else {
		l = l.WithField(logVaultName, p.name)
	}

	if err = matchFilter(policy, req, msg); err != nil {
		l.Error(err)
		return "", errors.Wrap(err, http.StatusForbidden)
	}

	if err = s.callPolicyHook(ctx, req); err != nil {
		l.Error(err)
		return "", err
	}

	l.Info("Requesting signing operation")

	level := log.DebugLevel
	if policy.LogPayloads {
		level = log.InfoLevel
	}
	l.WithField(logRaw, hex.EncodeToString(req.Message)).Log(level, "About to sign raw bytes")

	signFunc := func(ctx context.Context, message []byte, key vault.StoredKey) (cryptoutils.Signature, error) {
		if err = s.config.Watermark.IsSafeToSign(req.PublicKeyHash, message, msg); err != nil {
			err = errors.Wrap(err, http.StatusConflict)
			l.Error(err)
			return nil, err
		}
		return p.vault.SignMessage(ctx, message, p.key)
	}

	var sig cryptoutils.Signature
	if s.config.Interceptor != nil {
		err = s.config.Interceptor(&SignInterceptorOptions{
			Address: req.PublicKeyHash,
			Vault:   p.vault.Name(),
			Req:     msg.MessageKind(),
			Stat:    opStat,
		}, func() (err error) {
			sig, err = signFunc(ctx, req.Message, p.key)
			return err
		})
	} else {
		sig, err = signFunc(ctx, req.Message, p.key)
	}
	if err != nil {
		return "", err
	}

	sig = cryptoutils.CanonizeSignature(sig)

	l.WithField("raw", sig).Debug("Signed bytes")

	encodedSig, err := tezos.EncodeSignature(sig) // leave signature type
	if err != nil {
		return "", err
	}

	l.Debugf("Encoded signature: %s", encodedSig)
	l.Infof("Signed %s successfully", msg.MessageKind())

	return encodedSig, nil
}

func (s *Signatory) listPublicKeys(ctx context.Context) (ret map[string]*keyVaultPair, list []*keyVaultPair, err error) {
	ret = make(map[string]*keyVaultPair)
	for name, v := range s.vaults {
		var vaultKeys []*keyVaultPair
		iter := v.ListPublicKeys(ctx)
	keys:
		for {
			key, err := iter.Next()
			if err != nil {
				switch {
				case stderr.Is(err, vault.ErrDone):
					break keys
				case stderr.Is(err, vault.ErrKey):
					continue keys
				default:
					return nil, nil, err
				}
			}

			if !cryptoutils.PublicKeySuitableForTezos(key.PublicKey()) {
				continue
			}

			pkh, err := tezos.EncodePublicKeyHash(key.PublicKey())
			if err != nil {
				return nil, nil, err
			}
			p := &keyVaultPair{pkh: pkh, key: key, vault: v, name: name}
			s.cache.push(pkh, p)

			ret[pkh] = p
			vaultKeys = append(vaultKeys, p)
		}
		if len(vaultKeys) == 0 {
			s.logger().Error("No valid keys found in the vault ", name)
		}
		list = append(list, vaultKeys...)
	}
	return ret, list, nil
}

// ListPublicKeys retrieve the list of all public keys supported by the current configuration
func (s *Signatory) ListPublicKeys(ctx context.Context) ([]*PublicKey, error) {
	_, list, err := s.listPublicKeys(ctx)
	if err != nil {
		return nil, err
	}

	ret := make([]*PublicKey, len(list))
	for i, p := range list {
		enc, err := tezos.EncodePublicKey(p.key.PublicKey())
		if err != nil {
			return nil, err
		}
		ret[i] = &PublicKey{
			PublicKey:     enc,
			PublicKeyHash: p.pkh,
			VaultName:     p.vault.Name(),
			ID:            p.key.ID(),
			Policy:        s.fetchPolicyOrDefault(p.pkh),
		}
		ret[i].Active = ret[i].Policy != nil
	}
	return ret, nil
}

func (s *Signatory) getPublicKey(ctx context.Context, keyHash string) (*keyVaultPair, error) {
	cached := s.cache.get(keyHash)
	if cached != nil {
		return cached, nil
	}

	s.logger().WithField(logPKH, keyHash).Debugf("Fetching public key for: %s", keyHash)

	keys, _, err := s.listPublicKeys(ctx)
	if err != nil {
		return nil, err
	}

	if p, ok := keys[keyHash]; ok {
		return p, nil
	}
	return nil, ErrVaultNotFound
}

// GetPublicKey retrieve the public key from a vault
func (s *Signatory) GetPublicKey(ctx context.Context, keyHash string) (*PublicKey, error) {
	p, err := s.getPublicKey(ctx, keyHash)
	if err != nil {
		return nil, err
	}

	enc, err := tezos.EncodePublicKey(p.key.PublicKey())
	if err != nil {
		return nil, err
	}

	return &PublicKey{
		PublicKey:     enc,
		PublicKeyHash: keyHash,
		VaultName:     p.vault.Name(),
		ID:            p.key.ID(),
		Policy:        s.fetchPolicyOrDefault(keyHash),
	}, nil
}

// Unlock unlock all the vaults
func (s *Signatory) Unlock(ctx context.Context) error {
	for _, v := range s.vaults {
		if unlocker, ok := v.(vault.Unlocker); ok {
			if err := unlocker.Unlock(ctx); err != nil {
				return err
			}
		}
	}
	s.cache.drop()
	return nil
}

type PolicyHook struct {
	Address string
	Auth    auth.AuthorizedKeysStorage
}

// Config represents Signatory configuration
type Config struct {
	Policy       map[string]*Policy
	Vaults       map[string]*config.VaultConfig
	Interceptor  SignInterceptor
	Watermark    Watermark
	Logger       log.FieldLogger
	VaultFactory vault.Factory
	PolicyHook   *PolicyHook
}

// New returns Signatory instance
func New(ctx context.Context, c *Config) (*Signatory, error) {
	s := &Signatory{
		config: *c,
		vaults: make(map[string]vault.Vault, len(c.Vaults)),
	}

	// Initialize vaults
	for name, vc := range c.Vaults {
		if vc == nil {
			continue
		}

		l := s.logger().WithFields(log.Fields{
			logVault:     vc.Driver,
			logVaultName: name,
		})

		l.Info("Initializing vault")

		factory := c.VaultFactory
		if factory == nil {
			factory = vault.Registry()
		}
		v, err := factory.New(ctx, vc.Driver, &vc.Config)
		if err != nil {
			return nil, err
		}
		s.vaults[name] = v
	}

	return s, nil
}

// Ready returns true if all backends are ready
func (s *Signatory) Ready(ctx context.Context) (bool, error) {
	for _, v := range s.vaults {
		if rc, ok := v.(vault.ReadinessChecker); ok {
			if ok, err := rc.Ready(ctx); !ok || err != nil {
				return ok, err
			}
		}
	}
	return true, nil
}

// PreparePolicy prepares policy data by hashing keys etc
func PreparePolicy(src config.TezosConfig) (map[string]*Policy, error) {
	policy := make(map[string]*Policy, len(src))
	for k, v := range src {
		if v == nil {
			policy[k] = nil // default policy
			continue
		}

		pol := Policy{
			LogPayloads: v.LogPayloads,
		}

		if v.Allow != nil {
			pol.AllowedRequests = make([]string, 0, len(v.Allow))
			for req := range v.Allow {
				pol.AllowedRequests = append(pol.AllowedRequests, req)
			}
			sort.Strings(pol.AllowedRequests)

			if ops, ok := v.Allow["generic"]; ok {
				pol.AllowedOps = make([]string, len(ops))
				copy(pol.AllowedOps, ops)
				sort.Strings(pol.AllowedOps)
			}
		} else if v.AllowedKinds != nil || v.AllowedOperations != nil {
			if v.AllowedOperations != nil {
				pol.AllowedRequests = make([]string, len(v.AllowedOperations))
				copy(pol.AllowedRequests, v.AllowedOperations)
				sort.Strings(pol.AllowedRequests)
			}
			if v.AllowedKinds != nil {
				pol.AllowedOps = make([]string, len(v.AllowedKinds))
				copy(pol.AllowedOps, v.AllowedKinds)
				sort.Strings(pol.AllowedOps)
			}
			log.Warnln("`allowed_operations` and `allowed_kinds` options are deprecated. Use `allow` instead:")
			type example struct {
				Allow map[string][]string `yaml:"allow"`
			}
			e := example{
				Allow: make(map[string][]string),
			}
			for _, r := range pol.AllowedRequests {
				e.Allow[r] = nil
			}
			if pol.AllowedOps != nil {
				e.Allow["generic"] = pol.AllowedOps
			}
			out, err := yaml.Marshal(&e)
			if err != nil {
				panic(err)
			}
			pipe := log.StandardLogger().WriterLevel(log.WarnLevel)
			pipe.Write(out)
			pipe.Close()
		}

		if v.AuthorizedKeys != nil {
			keys := v.AuthorizedKeys.List()
			pol.AuthorizedKeyHashes = make([]string, len(keys))
			for i, k := range keys {
				pub, err := tezos.ParsePublicKey(k)
				if err != nil {
					return nil, err
				}
				pol.AuthorizedKeyHashes[i], err = tezos.EncodePublicKeyHash(pub)
				if err != nil {
					return nil, err
				}
			}
		}
		policy[k] = &pol
	}
	return policy, nil
}
