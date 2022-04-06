# Signatory

## Configuration

Signatory configuration is specified in a YAML file. Use the `signatory.yaml` file as a template to get started.

You can configure multiple `vault`s. Each `vault` should be configured to use a backend. Same backend can be used in more than one `vault`.

The configuration file is shared between `signatory` and `signatory-cli`.

### Configuration example

```yaml
server:
  # Address for the main HTTP server to listen on
  address: :6732
  # Address for the utility HTTP server (for Prometheus metrics) to listen on
  utility_address: :9583
  # List of authorized public keys. Sign operation must be authenticated if present
  # Nested lists are allowed
  authorized_keys:
    - &authorized_key edpktpQKJF4vRodmSfT3h6LrYisshQuJeoybUxB9c8s3b1QymvisHC
    - &authorized_keys_list
      - edpkubVAm7SttSV2WigeSoB7fAnr612PJo9DnhCgQyXakjaMeweN1D
      - &picked_key edpkuNVUYqMD61DyQ7N378nGCjCnQ3h2BiEsfeeY64kwKVJAJ4C9sY

vaults:
  # Name is used to identify backend during import process
  kms:
    driver: cloudkms
    config:
      # See backend specific documentation
      project: signatory
      location: europe-north1
      key_ring: hsm-ring
  azure:
    driver: azure
    config:
      # See backend specific documentation
      vault: https://signatory.vault.azure.net/
      tenant_id: cf5dd0ba-d3a3-4f3f-a688-06d12672f8ed
      client_id: 5d29a974-edd0-4659-b933-7d9c56726649
      client_pkcs12_certificate: principal.pfx
  yubi:
    driver: yubihsm
    config:
      # See backend specific documentation
      address: localhost:12345
      password: password
      auth_key_id: 1

# List enabled public keys hashes here
tezos:
  # Default policy allows "block" and "endorsement" operations
  tz1Wz4ZabKRsz842Xuzy4a7CcWADfPVsPKus:
  # Explicit policy
  tz3MhmeqpudUqEX8PYTbNDF3CVcnnjNQoo8N:
    # Setting `log_payloads` to `true` will cause Signatory to log operation
    # payloads to `stdout`. This may be desirable for audit and investigative
    # purposes.
    log_payloads: true
    allowed_operations:
      # List of [generic, block, endorsement]
      - generic
      - block
      - endorsement
    allowed_kinds:
      # List of [endorsement, ballot, reveal, transaction, origination, delegation, seed_nonce_revelation, activate_account]
      - transaction
      - endorsement
    authorized_keys:
      # Allow sign operation only for clients specified below. Same syntax as `server/authorized_key`
      - *authorized_key
```

## Backends

* [Google Cloud KMS](/pkg/vault/cloudkms/README.md)
* [Azure](/pkg/vault/azure/README.md)
* [YubiHSM2](/pkg/vault/yubi/README.md)

---

## Signatory service

Signatory service is used for signing operations and implements Tezos specific HTTP external signer API

```
A Tezos Remote Signer for signing block-chain operations with private keys

Usage:
  signatory [flags]
  signatory [command]

Available Commands:
  help        Help about any command
  serve       Run a server

Flags:
  -c, --config string   Config file path (default "signatory.yaml")
  -h, --help            help for signatory
      --log string      Log level: [error, warn, info, debug, trace] (default "info")
```

### Prometheus metrics and health service

Signatory exposes Prometheus metrics and health status on the address specified in `utility_address` configuration parameter. The default value is `:9583`.

#### Prometheus metrics

Metrics include counters and histograms that track signing operations and errors.

The metrics are intended to be scraped using the Prometheus time series database. We also publish a ready-made Grafana dashboard that users can use to visualize the operation of their signing operations. (TODO: publish Grafana dashboard)

`localhost:9583/metrics`

#### Health service

The health service endpoint can be used to test if the service is running correctly and is ready to sign requests.

This endpoint is useful for monitoring, or declarative tests as part of deployment playbooks or Kubernetes manifests.

`localhost:9583/healthz`

### Testing

To test the signing operation, you can send a post to Signatory. In this example, we are sending a dummy operation of type `02`, which is an `endorsement` operation type.

```sh
curl -XPOST \
    -d '"02111111111111111111"' \
    localhost:8003/keys/tz3Tm6UTWmPAZJaNSPAQNiMiyFSHnRXrkcHj
```

If you receive an error from curl and on the signatory console, you will have to investigate. If it was successful, you should see output similar to:

```json
{"signature":"p2sigR4JTRTMkT4XC4NgVuGdhZDbgaaSZpNPUserkyMCTY1GQJTFpCuihFRVk9n7YaNjA5U3cNcvJPRm7C9G5A1hsLsesVPcMu"}
```

---

## Signatory command line tool

Signatory service is used for importing of private keys and obtaining information about available key pairs and their policies.

```
A Tezos Remote Signer for signing block-chain operations with private keys

Usage:
  signatory-cli import [flags]

Flags:
  -h, --help              help for import
  -o, --opt string        Options to be passed to the backend. Syntax: key:val[,...]
      --password string   Password for private key(s)
      --vault string      Vault name for importing

Global Flags:
  -c, --config string   Config file path (default "signatory.yaml")
      --log string      Log level: [error, warn, info, debug, trace] (default "info")
```

### Import a private key

```sh
signatory-cli -c CONFIG import --vault VAULT PRIVATE_KEY
```

Example:

```sh
signatory-cli -c signatory.yaml import --vault yubi edsk3rsARzj7f8PEHXXUbLigMDCww75nPnzbFmSz19TLwzrYzF8uCB
```

### List keys

```sh
signatory-cli -c CONFIG list
```

Example:

```sh
signatory-cli -c signatory.yaml list
```

Example output:

```
INFO[0000] Initializing vault                            vault=cloudkms vault_name=kms
INFO[0000] Initializing vault                            vault=azure vault_name=azure
Public Key Hash:    tz3VfoCwiQyMNYnaseFLFAjN9AQJQnhvddjG
Vault:              CloudKMS
ID:                 projects/signatory-testing/locations/europe-north1/keyRings/hsm-ring/cryptoKeys/hsm-key/cryptoKeyVersions/1
Allowed Operations: [block endorsement]
Allowed Kinds:      []

Public Key Hash:    tz3ZqyLdKy2doLbw7yghLPz2TWWZdxeLGKVx
Vault:              CloudKMS
ID:                 projects/signatory-testing/locations/europe-north1/keyRings/hsm-ring/cryptoKeys/hsm-key/cryptoKeyVersions/2
*DISABLED*

Public Key Hash:    tz3aTwpna6m9qsw4YZVFad1nsm5cGgWHVQ8R
Vault:              CloudKMS
ID:                 projects/signatory-testing/locations/europe-north1/keyRings/hsm-ring/cryptoKeys/signatory-imported-1RG8mJUH8P5ncMEMypfkno98Gpq/cryptoKeyVersions/1
Allowed Operations: [block endorsement generic]
Allowed Kinds:      [endorsement transaction]

Public Key Hash:    tz3VkMSRVjLwEoUgZNJwjoD6YHeBDXyWiBaY
Vault:              Azure
ID:                 https://signatory.vault.azure.net/keys/key0/fa9607734e58485181d19da901e725b9
*DISABLED*

```