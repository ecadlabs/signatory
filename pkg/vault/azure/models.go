package azure

import (
	"github.com/ecadlabs/signatory/pkg/jwk"
)

type keyVaultError struct {
	Code       string         `json:"code"`
	Message    string         `json:"message"`
	InnerError *keyVaultError `json:"innererror"`
}

type keyVaultErrorResponse struct {
	Error *keyVaultError `json:"error"`
}

type keyListResult struct {
	NextLink string     `json:"nextLink"`
	Value    []*keyItem `json:"value"`
}

type keyItem struct {
	Attributes keyAttributes          `json:"attributes"`
	KeyID      string                 `json:"kid"`
	Managed    bool                   `json:"managed"`
	Tags       map[string]interface{} `json:"tags"`
}

type keyBundle struct {
	Attributes keyAttributes          `json:"attributes"`
	Key        jwk.JWK                `json:"key"`
	Managed    bool                   `json:"managed"`
	Tags       map[string]interface{} `json:"tags"`
}

type keyAttributes struct {
	Created       int    `json:"created"`
	Enabled       bool   `json:"enabled"`
	Exp           int    `json:"exp"`
	Nbf           int    `json:"nbf"`
	RecoveryLevel string `json:"recoveryLevel"`
	Updated       int    `json:"updated"`
}

type signRequest struct {
	Algorithm string `json:"alg"`
	Value     string `json:"value"`
}

type keyOperationResult struct {
	KeyID string `json:"kid"`
	Value string `json:"value"`
}
