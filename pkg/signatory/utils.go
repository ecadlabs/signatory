package signatory

import (
	"github.com/ecadlabs/gotez/b58"
	"github.com/ecadlabs/signatory/pkg/signatory/request"
)

func AuthenticatedBytesToSign(req *SignRequest) ([]byte, error) {
	pkh, err := b58.ParsePublicKeyHash([]byte(req.PublicKeyHash))
	if err != nil {
		return nil, err
	}
	keyHashBytes := pkh.ToBinary()
	data := make([]byte, 2+len(req.Message)+len(keyHashBytes))
	data[0] = 4
	data[1] = 1
	copy(data[2:], keyHashBytes)
	copy(data[2+len(keyHashBytes):], req.Message)
	return data, nil
}

type operationsStat map[string]int

// getOperationsStat returns statistics of operations
func getOperationsStat(u *request.GenericOperationRequest) operationsStat {
	ops := make(operationsStat)
	for _, o := range u.Operations {
		ops[o.OperationKind()]++
	}
	return ops
}
