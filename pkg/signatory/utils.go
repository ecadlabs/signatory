package signatory

import (
	"bytes"

	"github.com/ecadlabs/gotez/v2/encoding"
	"github.com/ecadlabs/gotez/v2/protocol/core"
	proto_latest "github.com/ecadlabs/gotez/v2/protocol/latest"
	proto_v1 "github.com/ecadlabs/gotez/v2/protocol/proto_022_PsRiotum"
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

func getOperationsStat(req *SignRequest, msg core.SignRequest) (operationsStat, bool) {
	ops := make(operationsStat)
	switch req.SignOptions.Version.ToUint8() {
	case 1:
		if msg, ok := msg.(*proto_v1.GenericOperationSignRequest); ok {
			for _, o := range msg.Contents {
				ops[core.GetOperationKind(o)]++
			}
			return ops, true
		}
	default:
		if msg, ok := msg.(*proto_latest.GenericOperationSignRequest); ok {
			for _, o := range msg.Contents {
				ops[core.GetOperationKind(o)]++
			}
			return ops, true
		}
	}
	return nil, false
}

func getSignRequest(req *SignRequest) (core.SignRequest, error) {
	var decodeErr error
	switch req.SignOptions.Version.ToUint8() {
	case 1:
		var msgV1 proto_v1.SignRequest
		_, decodeErr = encoding.Decode(req.Message, &msgV1)
		if decodeErr == nil {
			return msgV1, nil
		}
	default:
		var msgLatest proto_latest.SignRequest
		_, decodeErr = encoding.Decode(req.Message, &msgLatest)
		if decodeErr == nil {
			return msgLatest, nil
		}
	}
	return nil, decodeErr
}

func getOperations(req *SignRequest, msg core.SignRequest) ([]core.OperationContents, bool) {
	var operations []core.OperationContents
	switch req.SignOptions.Version.ToUint8() {
	case 1:
		if msg, ok := msg.(*proto_v1.GenericOperationSignRequest); ok {
			contents := msg.Contents
			operations = make([]core.OperationContents, len(contents))
			for i, op := range contents {
				operations[i] = op
			}
			return operations, true
		}
	default:
		if msg, ok := msg.(*proto_latest.GenericOperationSignRequest); ok {
			contents := msg.Contents
			operations = make([]core.OperationContents, len(contents))
			for i, op := range contents {
				operations[i] = op
			}
			return operations, true
		}
	}
	return nil, false
}
