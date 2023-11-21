package tezos

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

	"github.com/ecadlabs/gotez/b58"
	"github.com/ecadlabs/gotez/encoding"
	"github.com/ecadlabs/signatory/pkg/auth"
	"github.com/ecadlabs/signatory/pkg/config"
	"github.com/ecadlabs/signatory/pkg/crypt"
	"github.com/ecadlabs/signatory/pkg/errors"
	"github.com/ecadlabs/signatory/pkg/hashmap"
	"github.com/ecadlabs/signatory/pkg/tezos/request"
	"github.com/ecadlabs/signatory/pkg/utils"
	"github.com/ecadlabs/signatory/pkg/vault/manager"
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
	Address crypt.PublicKeyHash
	Vault   string
	Req     string
	Stat    operationsStat
}

// PublicKeyPolicy contains policy data related to the key
type PublicKeyPolicy struct {
	AllowedRequests     []string
	AllowedOps          []string
	LogPayloads         bool
	AuthorizedKeyHashes []crypt.PublicKeyHash
	AuthorizedJwtUsers  []string
}

// PublicKey contains public key with its hash
type PublicKey struct {
	*manager.PublicKey
	Policy *PublicKeyPolicy
	Active bool
}

// Signer is a struct coordinate signatory action and select vault according to the key being used
type Signer struct {
	*manager.Manager
	config Config
}

// SignRequest represents a sign request which may be authenticated with the client key
type SignRequest struct {
	ClientPublicKeyHash crypt.PublicKeyHash // optional, see policy
	PublicKeyHash       crypt.PublicKeyHash
	Source              net.IP // optional caller address
	Message             []byte
}

func (s *Signer) logger() log.FieldLogger {
	if s.config.Logger != nil {
		return s.config.Logger
	}
	return log.StandardLogger()
}

var defaultPolicy = PublicKeyPolicy{
	AllowedRequests: []string{"block", "preendorsement", "endorsement"},
}

func (s *Signer) fetchPolicyOrDefault(keyHash crypt.PublicKeyHash) *PublicKeyPolicy {
	val, ok := s.config.Policy.Get(keyHash)
	if !ok {
		return nil
	}
	if val != nil {
		return val
	}
	return &defaultPolicy
}

func matchFilter(policy *PublicKeyPolicy, req *SignRequest, msg request.SignRequest) error {
	if policy.AuthorizedKeyHashes != nil {
		if req.ClientPublicKeyHash == nil {
			return errors.New("authentication required")
		}

		var allowed bool
		cpkh := req.ClientPublicKeyHash.ToComparable()
		for _, k := range policy.AuthorizedKeyHashes {
			if k.ToComparable() == cpkh {
				allowed = true
				break
			}
		}

		if !allowed {
			return fmt.Errorf("client `%s' is not allowed", req.ClientPublicKeyHash)
		}
	}

	kind := msg.RequestKind()
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

	if ops, ok := msg.(*request.GenericOperationRequest); ok {
		for _, op := range ops.Operations {
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

/*
func jwtVerifyUser(user string, policy *PublicKeyPolicy, req *SignRequest) error {
	fmt.Println("jwtVerifyUser", user, policy.AuthorizedJwtUsers)
	authorized := false
	if policy.AuthorizedJwtUsers != nil {
		fmt.Println("AuthorizedJwtUsers", policy.AuthorizedJwtUsers)
		for _, u := range policy.AuthorizedJwtUsers {
			if u == user {
				authorized = true
				break
			}
		}
		if !authorized {
			return fmt.Errorf("user `%s' is not authorized to access %s", user, req.PublicKeyHash)
		}
	}
	fmt.Println("AuthorizedJwtUsers nil: ", authorized)
	return nil
}
*/

func (s *Signer) callPolicyHook(ctx context.Context, req *SignRequest) error {
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
		PublicKeyHash: string(req.PublicKeyHash.ToBase58()),
		Nonce:         nonce[:],
	}
	if req.ClientPublicKeyHash != nil {
		hookReq.ClientKeyHash = string(req.ClientPublicKeyHash.ToBase58())
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
		pkh, err := b58.ParsePublicKeyHash([]byte(pl.PublicKeyHash))
		if err != nil {
			errors.Wrap(err, http.StatusForbidden)
		}
		pub, err := s.config.PolicyHook.Auth.GetPublicKey(ctx, pkh)
		if err != nil {
			errors.Wrap(err, http.StatusForbidden)
		}
		sig, err := crypt.ParseSignature([]byte(reply.Signature))
		if err != nil {
			return err
		}
		if !sig.Verify(pub, reply.Payload) {
			return errors.Wrap(errors.New("invalid hook reply signature"), http.StatusForbidden)
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
func (s *Signer) Sign(ctx context.Context, req *SignRequest) (crypt.Signature, error) {
	l := s.logger().WithField(logPKH, req.PublicKeyHash)

	if req.ClientPublicKeyHash != nil {
		l = l.WithField(logClient, req.ClientPublicKeyHash)
	}

	policy := s.fetchPolicyOrDefault(req.PublicKeyHash)
	if policy == nil {
		err := fmt.Errorf("%s is not listed in config", strings.Replace(string(req.PublicKeyHash.ToBase58()), "\n", "", -1))
		l.WithField(logRaw, hex.EncodeToString(req.Message)).Error(err)
		return nil, errors.Wrap(err, http.StatusForbidden)
	}

	/*
		// TODO: Must be a part of HTTP server
		u := ctx.Value("user")
		if u != nil {
			if err := jwtVerifyUser(u.(string), policy, req); err != nil {
				l.WithField(logRaw, hex.EncodeToString(req.Message)).Error(err)
				return nil, errors.Wrap(err, http.StatusForbidden)
			}
		}
	*/

	var msg request.SignRequest
	_, err := encoding.Decode(req.Message, &msg)
	if err != nil {
		l.WithField(logRaw, hex.EncodeToString(req.Message)).Error(strings.Replace(err.Error(), "\n", "", -1))
		return nil, errors.Wrap(err, http.StatusBadRequest)
	}

	l = l.WithField(logReq, msg.RequestKind())

	if m, ok := msg.(request.WithWatermark); ok {
		l = l.WithFields(log.Fields{logChainID: string(m.GetChainID().ToBase58()), logLevel: m.GetLevel()})
	}

	var opStat operationsStat
	if ops, ok := msg.(*request.GenericOperationRequest); ok {
		opStat = getOperationsStat(ops)
		l = l.WithFields(log.Fields{logOps: opStat, logTotalOps: len(ops.Operations)})
	}

	p, err := s.Manager.GetPublicKey(ctx, req.PublicKeyHash)
	if err != nil {
		l.Error(err)
		return nil, err
	}
	l = l.WithFields(log.Fields{logVault: p.VaultName, logVaultName: p.VaultInstanceName})

	if err = matchFilter(policy, req, msg); err != nil {
		l.Error(err)
		return nil, errors.Wrap(err, http.StatusForbidden)
	}

	if err = s.callPolicyHook(ctx, req); err != nil {
		l.Error(err)
		return nil, err
	}

	level := log.DebugLevel
	if policy.LogPayloads {
		level = log.InfoLevel
	}
	l.WithField(logRaw, hex.EncodeToString(req.Message)).Log(level, "About to sign raw bytes")

	digest := crypt.DigestFunc(req.Message)
	signFunc := func() (crypt.Signature, error) {
		if err = s.config.Watermark.IsSafeToSign(req.PublicKeyHash, msg, &digest); err != nil {
			err = errors.Wrap(err, http.StatusConflict)
			l.Error(err)
			return nil, err
		}
		return s.Manager.SignBytes(ctx, req.PublicKeyHash, req.Message)
	}

	var sig crypt.Signature
	if s.config.Interceptor != nil {
		err = s.config.Interceptor(&SignInterceptorOptions{
			Address: req.PublicKeyHash,
			Vault:   p.VaultName,
			Req:     msg.RequestKind(),
			Stat:    opStat,
		}, func() (err error) {
			sig, err = signFunc()
			return err
		})
	} else {
		sig, err = signFunc()
	}
	if err != nil {
		return nil, err
	}

	l.Infof("Signed %s successfully", msg.RequestKind())
	return sig, nil
}

// ListPublicKeys retrieve the list of all public keys supported by the current configuration
func (s *Signer) ListPublicKeys(ctx context.Context) ([]*PublicKey, error) {
	list, err := s.Manager.ListPublicKeys(ctx)
	if err != nil {
		return nil, err
	}
	ret := make([]*PublicKey, len(list))
	for i, p := range list {
		ret[i] = &PublicKey{
			PublicKey: p,
			Policy:    s.fetchPolicyOrDefault(p.Hash()),
		}
		ret[i].Active = ret[i].Policy != nil
	}
	return ret, nil
}

// GetPublicKey retrieve the public key from a vault
func (s *Signer) GetPublicKey(ctx context.Context, keyHash crypt.PublicKeyHash) (*PublicKey, error) {
	p, err := s.Manager.GetPublicKey(ctx, keyHash)
	if err != nil {
		return nil, err
	}
	return &PublicKey{
		PublicKey: p,
		Policy:    s.fetchPolicyOrDefault(keyHash),
	}, nil
}

type PolicyHook struct {
	Address string
	Auth    auth.AuthorizedKeysStorage
}

type Policy = hashmap.PublicKeyHashMap[*PublicKeyPolicy]

// Config represents Signatory configuration
type Config struct {
	manager.ManagerConfig
	Policy      Policy
	Interceptor SignInterceptor
	Watermark   Watermark
	PolicyHook  *PolicyHook
}

// PreparePolicy prepares policy data by hashing keys etc
func PreparePolicy(src config.TezosConfig) (out Policy, err error) {
	policy := make(Policy, len(src))
	src.ForEach(func(k crypt.PublicKeyHash, v *config.TezosPolicy) bool {
		if v == nil {
			policy.Insert(k, nil) // default policy
			return true
		}

		pol := PublicKeyPolicy{
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
			pol.AuthorizedKeyHashes = make([]crypt.PublicKeyHash, len(keys))
			for i, k := range keys {
				pol.AuthorizedKeyHashes[i] = k.Hash()
			}
		}

		if v.JwtUsers != nil {
			pol.AuthorizedJwtUsers = v.JwtUsers
		}

		policy.Insert(k, &pol)
		return true
	})
	return policy, err
}

func (s *Signer) Import(ctx context.Context, importerName string, secretKey string, passCB func() ([]byte, error), opt utils.Options) (*PublicKey, error) {
	pub, err := s.Manager.Import(ctx, importerName, secretKey, passCB, opt)
	if err != nil {
		return nil, err
	}
	ret := PublicKey{
		PublicKey: pub,
		Policy:    s.fetchPolicyOrDefault(pub.Hash()),
	}
	ret.Active = ret.Policy != nil
	return &ret, nil
}

func New(ctx context.Context, cfg *Config) (*Signer, error) {
	manager, err := manager.New(ctx, cfg)
	if err != nil {
		return nil, err
	}
	return &Signer{
		Manager: manager,
		config:  *cfg,
	}, nil
}
