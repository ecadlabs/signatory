# Integration test

The test ensures that Signatory can perform an authenticated sign operations
while assisting `octez-client`.

From the project tree root

```sh
docker build --no-cache -t signatory-test -f ./integration_test/Dockerfile .
docker run --rm  -e 'ENV_NODE_ADDR={...}' -e 'ENV_SECRET_KEY={...}' signatory-test
```

where `ENV_NODE_ADDR` is the name of a testnet node example: https://ghostnet.ecadinfra.com
and `ENV_SECRET_KEY` is an unencrypted private key of an implicit, funded account on the testnet
the private key of alice can be used: edsk3QoqBuvdamxouPhin7swCvkQNgq4jP5KZPbwWNnwdZpSpJiEbq

## Environment variables

| Name               | Default value                   | Description                                                         |
| ------------------ | ------------------------------- | ------------------------------------------------------------------- |
| ENV_SECRET_KEY     |                                 | Private key in Tezos Base58 format.                                 |
| ENV_NODE_ADDR      | https://ghostnet.ecadinfra.com  | Testnet node                                                        |

## Add new testnet endpoint in Github CI
To add a new testnet to the `testnet_endpoints` list in `.github/workflows/integration-tests.yaml` we also need to make sure to fund the wallet `tz3NxnbanoQ9hyn3wcxZ3q9XGCaNSvmARv3Z` with some XTZ on the new testnet
