package server

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"

	"github.com/ecadlabs/gotez"
	"github.com/ecadlabs/signatory/pkg/cryptoutils"
	"github.com/ecadlabs/signatory/pkg/signatory"
)

type Server struct {
	Address    string
	PrivateKey cryptoutils.PrivateKey
	Addresses  []net.IP
	Nets       []*net.IPNet
}

func (s *Server) Handler() (http.Handler, error) {
	pub := gotez.NewPublicKey(s.PrivateKey.Public())

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req signatory.PolicyHookRequest
		dec := json.NewDecoder(r.Body)
		if err := dec.Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		var ok bool
		for _, n := range s.Nets {
			if n.Contains(req.Source) {
				ok = true
				break
			}
		}
		if !ok {
			for _, a := range s.Addresses {
				if a.Equal(req.Source) {
					ok = true
					break
				}
			}
		}

		if s.PrivateKey != nil {
			var status int
			if ok {
				status = http.StatusOK
			} else {
				status = http.StatusForbidden
			}

			replyPl := signatory.PolicyHookReplyPayload{
				Status:        status,
				PublicKeyHash: pub.Hash().String(),
				Nonce:         req.Nonce,
			}

			if !ok {
				replyPl.Error = fmt.Sprintf("address %s is not allowed", req.Source)
			}

			buf, err := json.Marshal(&replyPl)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}

			sig, err := cryptoutils.Sign(s.PrivateKey, buf)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}

			s, err := gotez.NewSignature(sig)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}

			reply := signatory.PolicyHookReply{
				Payload:   buf,
				Signature: s.String(),
			}

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			json.NewEncoder(w).Encode(&reply)
		} else {
			var status int
			if ok {
				status = http.StatusNoContent
			} else {
				status = http.StatusForbidden
			}
			w.WriteHeader(status)
		}
	}), nil
}

func (s *Server) New() *http.Server {
	h, err := s.Handler()
	if err != nil {
		return nil
	}
	return &http.Server{
		Handler: h,
		Addr:    s.Address,
	}
}
