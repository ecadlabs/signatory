package errors

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
	return withHTTPStatus{error: e, status: status}
}
