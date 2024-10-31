package integrationtesting

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"net"
	"net/http"
	"sort"

	"github.com/ecadlabs/gotez/v2/crypt"
	"github.com/ecadlabs/gotez/v2/protocol/core"
	"github.com/ecadlabs/gotez/v2/protocol/latest"
	"github.com/ecadlabs/signatory/integration_testing/tezbox"
)

const (
	tezboxVersion  = "v20.3"
	regularBalance = 50000
	bakerBalance   = 2000000
)

var (
	tezboxProtocol = &core.Proto020PsParisC
)

func genAccount(balance uint64) (*tezbox.AccountConfig, error) {
	var k ed25519.PrivateKey
	_, k, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	priv := crypt.Ed25519PrivateKey(k)
	return &tezbox.AccountConfig{
		PrivateKey: "unencrypted:" + priv.String(),
		PublicKey:  priv.Public().ToProtocol(),
		Balance:    balance,
	}, nil
}

func genBaseConfig() (*tezbox.ServiceConfig, error) {
	bakers := make(tezbox.Accounts)
	for i := 0; i < 3; i++ {
		x, err := genAccount(bakerBalance)
		if err != nil {
			return nil, err
		}
		bakers[fmt.Sprintf("baker%d", i+1)] = x
	}
	regular := make(tezbox.Accounts)
	x, err := genAccount(regularBalance)
	if err != nil {
		return nil, err
	}
	regular["alice"] = x
	if x, err = genAccount(regularBalance); err != nil {
		return nil, err
	}
	regular["bob"] = x
	return &tezbox.ServiceConfig{
		Version:  tezboxVersion,
		Protocol: tezboxProtocol,
		Accounts: &tezbox.AccountsConfig{
			Bakers:  bakers,
			Regular: regular,
		},
	}, nil
}

func newRemoteSignerConfig(pub crypt.PublicKey, addr net.Addr, balance uint64) *tezbox.AccountConfig {
	return &tezbox.AccountConfig{
		PrivateKey: fmt.Sprintf("http://host.docker.internal:%d/%v", addr.(*net.TCPAddr).Port, pub.Hash()),
		PublicKey:  pub.ToProtocol(),
		Balance:    balance,
	}
}

func startHTTPServer(srv *http.Server) (net.Listener, error) {
	l, err := net.Listen("tcp", ":0")
	if err != nil {
		return nil, err
	}
	go srv.Serve(l)
	return l, nil
}

func opKinds() []string {
	var ops []string
	for _, k := range latest.ListOperations() {
		ops = append(ops, k.OperationKind())
	}
	for _, k := range latest.ListPseudoOperations() {
		ops = append(ops, k.PseudoOperation())
	}
	sort.Strings(ops)
	return ops
}

func genEd25519Keys(n int) ([]crypt.Ed25519PrivateKey, error) {
	out := make([]crypt.Ed25519PrivateKey, n)
	for i := 0; i < n; i++ {
		_, k, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		out[i] = crypt.Ed25519PrivateKey(k)
	}
	return out, nil
}
