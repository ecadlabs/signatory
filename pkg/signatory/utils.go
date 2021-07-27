package signatory

import "github.com/ecadlabs/signatory/pkg/tezos"

func SignRequestAuthenticatedBytes(req *SignRequest) ([]byte, error) {
	keyHashBytes, err := tezos.EncodeBinaryPublicKeyHash(req.PublicKeyHash)
	if err != nil {
		return nil, err
	}
	data := make([]byte, 2+len(req.Message)+len(keyHashBytes))
	data[0] = 4
	data[1] = 1
	copy(data[2:], keyHashBytes)
	copy(data[2+len(keyHashBytes):], req.Message)
	return data, nil
}
