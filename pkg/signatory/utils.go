package signatory

import (
	"bytes"

	"github.com/ecadlabs/gotez/v2/encoding"
	"github.com/ecadlabs/gotez/v2/protocol/core"
	proto "github.com/ecadlabs/gotez/v2/protocol/latest"
)

func AuthenticatedBytesToSign(req *SignRequest) ([]byte, error) {
	var buf bytes.Buffer
	if err := encoding.Encode(&buf, &req.PublicKeyHash); err != nil {
		return nil, err
	}
	keyHashBytes := buf.Bytes()
	data := make([]byte, 2+len(req.Message)+len(keyHashBytes))
	data[0] = 4
	data[1] = 1
	copy(data[2:], keyHashBytes)
	copy(data[2+len(keyHashBytes):], req.Message)
	return data, nil
}

type operationsStat map[string]int

// getOperationsStat returns statistics of operations
func getOperationsStat(u *proto.GenericOperationSignRequest) operationsStat {
	ops := make(operationsStat)
	for _, o := range u.Contents {
		ops[core.GetOperationKind(o)]++
	}
	return ops
}
