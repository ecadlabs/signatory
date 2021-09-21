package awskms_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/request"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/ecadlabs/signatory/pkg/config"
	"github.com/ecadlabs/signatory/pkg/server"
	"github.com/ecadlabs/signatory/pkg/signatory"
	"github.com/ecadlabs/signatory/pkg/tezos"
	"github.com/ecadlabs/signatory/pkg/vault"
	akms "github.com/ecadlabs/signatory/pkg/vault/aws"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

type testCase struct {
	name       string
	raw        string
	privkey    *ecdsa.PrivateKey
	pubkey     *ecdsa.PublicKey
	pkh        string
	statusCode int
}

var cases = make([]testCase, 1)

type mockKMSClient struct {
	akms.Kmsapi
}

func (m *mockKMSClient) ListKeys(input *kms.ListKeysInput) (*kms.ListKeysOutput, error) {
	pk0 := "0"
	trunk := false
	kls := make([]*kms.KeyListEntry, 1)
	kls[0] = &kms.KeyListEntry{KeyId: &pk0}

	return &kms.ListKeysOutput{
		Keys:      kls,
		Truncated: &trunk,
	}, nil
}

func (m *mockKMSClient) Sign(input *kms.SignInput) (*kms.SignOutput, error) {
	sign, err := ecdsa.SignASN1(rand.Reader, cases[0].privkey, input.Message)
	if err != nil {
		return nil, err
	}

	return &kms.SignOutput{
		Signature: sign,
	}, nil
}

func (m *mockKMSClient) GetPublicKeyWithContext(aws.Context, *kms.GetPublicKeyInput, ...request.Option) (*kms.GetPublicKeyOutput, error) {
	sv := "SIGN_VERIFY"
	kid := "0"

	pk, err := x509.MarshalPKIXPublicKey(cases[0].pubkey)
	if err != nil {
		return nil, err
	}

	return &kms.GetPublicKeyOutput{
		PublicKey: pk,
		KeyUsage:  &sv,
		KeyId:     &kid,
	}, nil
}

func TestAWSVault(t *testing.T) {

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	publicKey := &privateKey.PublicKey

	pub, err := tezos.EncodePublicKeyHash(publicKey)
	require.NoError(t, err)

	cases[0] = testCase{
		name:       "aws kms sign",
		raw:        "\"03a11f5f176e553a11cf184bb2b15f09f55dfc5dcb2d26d79bf5dd099d074d5f5d6c0079cae4c9a1885f17d3995619bf28636c4394458b820af19172c35000904e0000712c4c4270d9e7f512115310d8ec6acfcd878bef00\"",
		privkey:    privateKey,
		pubkey:     publicKey,
		pkh:        pub,
		statusCode: http.StatusOK,
	}

	mockSvc := &mockKMSClient{}

	conf := signatory.Config{
		Vaults:    map[string]*config.VaultConfig{"kms": {Driver: "awskms"}},
		Watermark: signatory.IgnoreWatermark{},
		VaultFactory: vault.FactoryFunc(func(ctx context.Context, name string, conf *yaml.Node) (vault.Vault, error) {
			return &akms.Vault{
				Kmsapi: mockSvc,
				Config: akms.Config{
					KeyID: "0",
				},
			}, nil
		}),
		Policy: map[string]*signatory.Policy{
			cases[0].pkh: {
				AllowedOperations: []string{"generic", "block", "endorsement"},
				AllowedKinds:      []string{"endorsement", "seed_nonce_revelation", "activate_account", "ballot", "reveal", "transaction", "origination", "delegation"},
			},
		},
	}

	signer, err := signatory.New(context.Background(), &conf)
	require.NoError(t, err)
	require.NoError(t, signer.Unlock(context.Background()))

	srv := server.Server{
		Signer: signer,
	}

	handler, err := srv.Handler()
	require.NoError(t, err)

	s := httptest.NewServer(handler)
	defer s.Close()

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			body := strings.NewReader(c.raw)
			u, _ := url.Parse(s.URL + "/keys/" + c.pkh)

			req, err := http.NewRequest("POST", u.String(), body)
			require.NoError(t, err)

			resp, err := s.Client().Do(req)
			require.NoError(t, err)

			require.Equal(t, c.statusCode, resp.StatusCode)
		})
	}
}
