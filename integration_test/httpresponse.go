package integrationtest

type SuccessResponse struct {
	Signature string `json:"signature"`
}

type FailureResponse struct {
	Id   string `json:"id"`
	Kind string `json:"kind"`
	Msg  string `json:"msg"`
}
