# Remote policy service

The remote policy service feature allows custom policy schemes beyond simple request and operation lookup
to be implemented externally.

The hook is called after the standard request type and operation checks. If the hook returned an error the sign operation is denied.

The service response can be authenticated using a signature. To do so the service public key hash must be added to the `authorized_keys` list.

## Configuration

```yaml
# config root
policy_hook:
    address: host:port
    # List of authorized keys in Tezos Base58 format
    authorized_keys:
        - pub1
        - pub2
        # ...
```

## API

### Request

```json
{
    // Base64 encoded raw incoming sign request
    "request": "base64",
    // Client address
    "source": "ip_address",
    // Requested public key hash in Tezos Base58 format
    "public_key_hash": "base58",
    // Client public key hash in Tezos Base58 format. Presents only if the incoming sign request was authenticated
    "client_key_hash": "base58",
    // One time nonce. Presents only if the policy service call is authenticated
    "nonce": "string"
}
```

### Authenticated reply

```json
{
    "payload": {
        // Must reflect the HTTP status code. The sign operation is allowed if the service returned 2xx
        "status": 200,
        // An optional error message is the status code is not 2xx
	    "error": "string",
        // The key used to sign the reply
	    "public_key_hash": "base58",
        // The request nonce
	    "nonce": "string"
    },
    // Payload signature in Tezos Base58 format
    "signature": "base58"
}
```

The signature is calculated from the `payload` JSON object **as it present in the request**.

### Non authenticated reply

Just the HTTP status code is inspected. The sign operation is allowed if the service returned 2xx

## Reference implementation

See [Approve List Service](cmd/approve-list-svc)