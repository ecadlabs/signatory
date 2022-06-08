---
id: tezos-client
title: Setup tezos-client to work with Signatory
---

The `tezos-client` is the official Octez CLI tool. This document shows how to configure a new account in `tezos-client` that Signatory backs.

`tezos-client` helps with verifying the setup and fills a need when operators of a baker require to transfer tokens out of their baking account to, for example, a hot wallet.

## Getting tezos-client

Download the latest `tezos-client` binary from the _Releases_ page at https://github.com/serokell/tezos-packaging 
Make sure to choose the appropriate binary for your operating system and architecture.

The `tezos-client` is also included `tezos-client` in the official Octez docker images.

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
tezos-client import secret key remote_signer_alias http://localhost:6732/tz1M3kiQUMPcTseo72i1twdiV4iTY5yiGNSz
```

You can then verify the details of this import by running the command:

```
$ tezos-client show address remote_signer_alias --show-secret
Hash: tz1M3kiQUMPcTseo72i1twdiV4iTY5yiGNSz
Public Key: edpkuNyLH57vRp2dyzeDSg2G7AarZcp29DQnkQaXrSNdkRkAE4B1ZA
Secret Key: http://localhost:6732/tz1M3kiQUMPcTseo72i1twdiV4iTY5yiGNSz
```

Note that we passed the `--show-secret` flag. This flag displays the URL to the remote signer but not the secret. In this case, the secret is in the remote signer's custody.

## Test a signing request using `tezos-client`

To sign arbitrary data using `tezos-client,` run the command:

```
tezos-client sign bytes 0x50deadbeef for octez_signer_local_key
```

If the remote signer allows signing operations with magic byte `0x05`, or "Michelson Data", the `tezos-client` will output a Signature.



