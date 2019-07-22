package vault

import "github.com/pkg/errors"

type withHttp struct {
	error
	code int
}

func (e *withHttp) Code() int {
	return e.code
}

func NewHttpError(msg string, code int) error {
	wrapped := errors.New(msg)
	return &withHttp{
		wrapped,
		code,
	}
}
