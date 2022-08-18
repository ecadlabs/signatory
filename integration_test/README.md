# Integration test

The test ensures that Signatory can perform an authenticated sign operations
while assisting `tezos-client`.

From the project tree root

```sh
docker build -t signatory-test -f ./integration_test/Dockerfile .
docker run -e 'ENV_ACTIVATION_KEY={...}' signatory-test
```

where `ENV_ACTIVATION_KEY` is a contents of an activation JSON key file obtained
from https://teztnets.xyz/jakartanet-faucet. The key must be activated using
`tezos-client activate account` command.

## Environment variables

| Name               | Default value                   | Description                                                         |
| ------------------ | ------------------------------- | ------------------------------------------------------------------- |
| ENV_ACTIVATION_KEY |                                 | Activation (faucet) key json. Used to generate private key.         |
| ENV_SECRET_KEY     |                                 | Private key in Tezos Base58 format. Overrides `ENV_ACTIVATION_KEY`. |
| ENV_NODE_ADDR      | https://rpc.jakartanet.teztnets.xyz | Testnet node                                                        |
