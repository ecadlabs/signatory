package errors

import (
	"errors"
)

type HTTPError interface {
	error
	HTTPStatus() int
}

type withHTTPStatus struct {
	error
	status int
}

func (w withHTTPStatus) HTTPStatus() int { return w.status }

func Wrap(e error, status int) HTTPError {
	if he, ok := e.(HTTPError); ok {
		return he // Ignore status
	}
	return withHTTPStatus{error: e, status: status}
}

func New(msg string) error {
	return errors.New(msg)
}
