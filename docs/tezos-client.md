---
id: tezos-client
title: tezos-client & Signatory
---

The `tezos-client` is the official Octez CLI tool. This document shows how to configure a new account in `tezos-client` that is backed by Signatory.

`tezos-client` is helpful for debugging, and also fills a need for when operators of a baker require to transfer tokens out of their baking account, to, for example, a hot-wallet.

## Getting tezos-client

`tezos-client` is included in the Octez docker images.

Download the latest `tezos-client` binary from the _Releases_ page at https://github.com/serokell/tezos-packaging 
Make sure to choose the appropriate binary for your operating system and architecture.

## tezos-client configuration

`tezos-client` stores configuration in the directory `${HOME}/.tezos-client` by default. 

The main configuration file for `tezos-client` is `${HOME}/.tezos-client/config`.

To display the configuration, run the command `tezos-client config show`

If no configuration exists, you can have `tezos-client` initialize a new configuration directory and file by running the command: 

```
tezos-client config init --endpoint https://jakartanet.ecadinfra.com
```

You can specify the preferred RPC address of the Tezos network you wish to use. You can find a list of public RPC nodes here: https://tezostaquito.io/docs/rpc_nodes/

## tezos-client listing and showing accounts

To list all accounts, `tezos-client` has been configured.

- `tezos-client list known addresses` Lists all addresses that are present in the `~/.tezos-client` configuration 

To display all information about a specific account, including the secret or secret pointer.

- `tezos-client show address ${alias} --show-secret` Displays all information about a given known address  

## Importing a remote signer account with `tezos-client`

For `tezos-client` to use a remote signer, tezos-client needs to know the address of the remote signer service.

`tezos-client` has a subcommand called `import secret key`, which allows users to import both actual secret key material and "import" a pointer to a remote signer that manages the secret.

Assuming you have a remote signer running on `http://localhost:6732/` and a key configured for `tz1M3kiQUMPcTseo72i1twdiV4iTY5yiGNSz`, you can then "import" a pointer to that secret into your `tezos-client` configuration.

```
tezos-client import secret key octez_signer_remote_ledger http://localhost:6732/tz1M3kiQUMPcTseo72i1twdiV4iTY5yiGNSz
```

You can then verify the details of this import by running the command:

```
$ tezos-client show address octez_signer_remote_ledger --show-secret
Hash: tz1M3kiQUMPcTseo72i1twdiV4iTY5yiGNSz
Public Key: edpkuNyLH57vRp2dyzeDSg2G7AarZcp29DQnkQaXrSNdkRkAE4B1ZA
Secret Key: http://localhost:6732/tz1M3kiQUMPcTseo72i1twdiV4iTY5yiGNSz
```

Note that we passed the `--show-secret` flag. This flag displays the URL to the remote signer but not the secret. In this case, the secret is in the remote signer's custody.

## Test a signing request using `tezos-client`

To sign arbitrary data using `tezos-client`, run the command:

```
tezos-client sign bytes 0x50deadbeef for octez_signer_local_key
```

If the remote signer allows signing operations with magic byte `0x05`, or "Michelson Data", the `tezos-client` will output a Signature.

## Display http requests

By adding the `--log-requests` or `-l`, to the `tezos-client`, you will see all the HTTP requests and responses between your `tezos-client` and the remote signer. Logging requests can be helpful for troubleshooting configuration problems.

```
$ tezos-client -l sign bytes 0x05deadbeef for remote_key
>>>>0: http://localhost:8732/version
<<<<0: 200 OK
  { "version": { "major": 13, "minor": 0, "additional_info": "release" },
    "network_version":
      { "chain_name": "TEZOS_JAKARTANET_2022-04-27T15:00:00Z",
        "distributed_db_version": 2, "p2p_version": 1 },
    "commit_info":
      { "commit_hash": "cb9f439e58c761e76ade589d1cdbd2abb737dc68",
        "commit_date": "2022-05-05 11:55:24 +0200" } }
>>>>1: http://localhost:8732/chains/main/blocks/head/protocols
<<<<1: 200 OK
  { "protocol": "PtJakart2xVj7pYXJBXrqHgd82rdkLey5ZeeGwDgPp9rhQUbSqY",
    "next_protocol": "PtJakart2xVj7pYXJBXrqHgd82rdkLey5ZeeGwDgPp9rhQUbSqY" }
>>>>2: http://localhost:6732/authorized_keys
<<<<2: 200 OK
  {}
>>>>3: http://localhost:6732/keys/tz1g7VaasrnCUmSmCKUcP8o61vMPscVkoxYL
  "05deadbeef"
<<<<3: 200 OK
  { "signature":
      "edsigu5xkT8xcTEECLri3WZG2QuFLgH47NgFaRKQpBnaUwPw9DfhKHSNTAcvLxqVqWc4i7SEiUciHcEUzmeKYQDQioKcBzayUaY" }
Signature: edsigu5xkT8xcTEECLri3WZG2QuFLgH47NgFaRKQpBnaUwPw9DfhKHSNTAcvLxqVqWc4i7SEiUciHcEUzmeKYQDQioKcBzayUaY
$
```

