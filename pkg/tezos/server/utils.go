package server

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/ecadlabs/signatory/pkg/errors"
)

// HTTPServer represents a subset of http.Server methods
type HTTPServer interface {
	ListenAndServe() error
	Shutdown(ctx context.Context) error
}

func jsonResponse(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func tezosJSONError(w http.ResponseWriter, err error) {
	type errorResponse []struct {
		ID   string `json:"id,omitempty"`
		Kind string `json:"kind,omitempty"`
		Msg  string `json:"msg,omitempty"`
	}

	var status int
	if e, ok := err.(errors.HTTPError); ok {
		status = e.HTTPStatus()
	} else {
		status = http.StatusInternalServerError
	}

	res := errorResponse{
		{
			ID:   "failure",
			Kind: "temporary",
			Msg:  err.Error(),
		},
	}
	jsonResponse(w, status, &res)
}

func jsonError(w http.ResponseWriter, err error) {
	type errorResponse struct {
		Error string `json:"error,omitempty"`
	}

	var status int
	if e, ok := err.(errors.HTTPError); ok {
		status = e.HTTPStatus()
	} else {
		status = http.StatusInternalServerError
	}

	res := errorResponse{
		Error: err.Error(),
	}

	jsonResponse(w, status, &res)
}
