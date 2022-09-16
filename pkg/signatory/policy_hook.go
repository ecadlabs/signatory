package signatory

import (
	"encoding/json"
)

type PolicyHookRequest struct {
	Request       []byte `json:"request"`
	Source        string `json:"source"`
	PublicKeyHash string `json:"public_key_hash"`
	Nonce         []byte `json:"nonce"`
}

type PolicyHookReplyPayload struct {
	Status        int    `json:"status"` // reflects the HTTP status
	Error         string `json:"error"`
	PublicKeyHash string `json:"public_key_hash"` // the key used to sign the reply
	Nonce         []byte `json:"nonce"`
}

type PolicyHookReply struct {
	Payload   json.RawMessage `json:"payload"`
	Signature string          `json:"signature"`
}
