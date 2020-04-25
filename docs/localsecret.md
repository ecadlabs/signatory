---
id: filebased
title: File-Based Secret Storage (Insecure)
---


For evaluation and prototyping purposes, Signatory file-based signer mode allows operation without an HSM or Key Vault service. By storing the secret key material in a JSON file, users can get Signatory up and running quickly for evaluation and development purposes.

## Signatory configuration for file-based secret storage

The documentation assumes you will use the official Signatory docker image, and that you have a Linux server operably configured with docker installed.

Place the following YAML in a file `/etc/signatory.yaml`

```yaml
server:
# Address/Port that Signatory listens on
address: :6732
# Address/Port that Signatory serves prometheus metrics on
utility_address: :9583

vaults:
# Name of vault
local_file_keys:
    driver: file
    config:
    file: /etc/secret.json

# List enabled public keys hashes here
tezos:
# Default policy allows "block" and "endorsement" operations
tz1Wk1Wdczh5BzyZ1uz2DW9xdFg9B5cFuGFm:
    log_payloads: true
    allowed_operations:
    # List of [generic, block, endorsement]
    - generic
    - block
    - endorsement
```

The `tz1Wk1Wdczh5BzyZ1uz2DW9xdFg9B5cFuGFm` key corresponds to the secret key that you will put in `/etc/secret.json`

Contents of `/etc/secret.json` is:

```json
[ { "name": "your_secret_key",
    "value":
      "unencrypted:edsk3DYwZpPmbNTRSdJW2wBeHoneNqjPt9Xj49Fnhcir6q47JpD5Vz" } ]
```

### Running Signatory

Next, you want to run the signatory docker image as follows:

```sh
docker run -it --rm \ 
    -v "$(realpath file.yaml):/app/signatory.yaml" \
    -v "$(realpath tezkeys/secret_keys):/etc/secret.json" \
    -p 6732:6732 \
    -p 9583:9583 \
    ecadlabs/signatory:latest serve -config /app/signatory.yaml
```

### Verify that signatory is working

You can test that signatory is working making a GET request using the Public Key Hash (PKH). Signatory will return a json payload containing the public key. 

```sh
curl signatory:6732/keys/tz1Wk1Wdczh5BzyZ1uz2DW9xdFg9B5cFuGFm
```

A response such as the following should be expected:

```json
{"public_key":"edpktn6UGrMQUjhWQJ5kY4qWoCp1sDZWkK5ugizTc5jHSifG1j3r8o"}
```

You can test the signing functionality by making a POST request as follows:

```sh
curl -XPOST \
    -d '"02111111111111111110"' \
    signatory:6732/keys/tz1Wk1Wdczh5BzyZ1uz2DW9xdFg9B5cFuGFm
```


Which should return an HTTP 200 OK with a payload similar to (this will only work once): 

```json
{"signature":"sigWetzF5zVM2qdYt8QToj7e5cNBm9neiPRc3rpePBDrr8N1brFbErv2YfXMSoSgemJ8AwZcLfmkBDg78bmUEzF1sf1YotnS"}
```

The payload on this request resembels a Tezos endorsement that would be emitted from a Tezos Baker node.
