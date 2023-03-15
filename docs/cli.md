---
id: cli
title: CLI
---

# Key Import using signatory-cli

To import a secret key, we will use the `signatory-cli import` command.

## Generating a key using octez-client

This is not the only way to generate keys to import in signatory. Any existing key can be imported in the vaults via signatory if the vault supports the key curve.

```bash
% octez-client gen keys import-p256 -s p256 --encrypted
Enter password to encrypt your key:
Confirm password:
```

```bash
% octez-client list known addresses
import-p256: tz3gxd1y7FdVJ81vzvuACcVjAc4ewXARQkLo (encrypted sk known)
```

The encrypted private key can be obtained from the `.octez-client/` directory

```bash
% cat ~/.octez-client/secret_keys
[ { "name": "import-p256",
    "value":
      "encrypted:p2esk**********************************************************" }]
```

## Importing the generated key using signatory-cli

A private key can be imported into any of the backend vaults (except: AWS,file & ledger) using the below command.
If you import an encrypted key, the `signatory-cli` command will prompt you for the password.

```bash
% ./signatory-cli import -c ./azure.yaml --base-dir ./ --vault azure
INFO[0000] Initializing vault                            vault=azure vault_name=azure
Enter secret key: 
Enter Password:
INFO[0002] Requesting import operation                   pkh=tz3gxd1y7FdVJ81vzvuACcVjAc4ewXARQkLo vault=Azure vault_name="https://forimport.vault.azure.net/"
INFO[0007] Successfully imported                         key_id="https://forimport.vault.azure.net/keys/signatory-imported-2CsWhgGqeRdkEiA0LFm3WyN5DxS/9d2266b388734ef0b14203e0943465d7" pkh=tz3gxd1y7FdVJ81vzvuACcVjAc4ewXARQkLo vault=Azure vault_name="https://forimport.vault.azure.net/"
```

If the import is successful, the `signatory-cli` will report the PKH (`tz3gxd1y7FdVJ81vzvuACcVjAc4ewXARQkLo` in the above example) of your newly imported secret which in turn can be used in the config YAML to add the policies.

**Note:** The PKH from Signatory and the PKH from `octez-client list known addresess` command must be the same.

Name of the key can also be provided with the import command.

```bash
% ./signatory-cli import -c ./azure.yaml --base-dir ./ --vault azure -o "name":test-name
INFO[0000] Initializing vault                            vault=azure vault_name=azure
Enter secret key: 
Enter Password: 
INFO[0003] Requesting import operation                   pkh=tz2PpBJj8utBU3Nxu7vexbdJVTcRxYfkfqcV vault=Azure vault_name="https://forimport.vault.azure.net/"
INFO[0009] Successfully imported                         key_id="https://forimport.vault.azure.net/keys/test-name/f503f20b309e4c8ea57982bd9736c412" pkh=tz2PpBJj8utBU3Nxu7vexbdJVTcRxYfkfqcV vault=Azure vault_name="https://forimport.vault.azure.net/"

./signatory-cli list -c ./azure.yaml --base-dir ./
INFO[0000] Initializing vault                            vault=azure vault_name=azure
Public Key Hash:    tz2PpBJj8utBU3Nxu7vexbdJVTcRxYfkfqcV
Vault:              Azure
ID:                 https://forimport.vault.azure.net/keys/test-name/f503f20b309e4c8ea57982bd9736c412
Active:             false
```

## Verifying the import operation using the list command

The import operation can be verified using the below list command.

```bash
 % ./signatory-cli list -c ./azure.yaml --base-dir ./
INFO[0000] Initializing vault                            vault=azure vault_name=azure

Public Key Hash:    tz3gxd1y7FdVJ81vzvuACcVjAc4ewXARQkLo
Vault:              Azure
ID:                 https://forimport.vault.azure.net/keys/signatory-imported-2Csev40hxBXjwo5wVVnRbonNaDl/ce48c88caf744549b638e97bf89acb1b
Active:             true
Allowed Operations: [block endorsement generic preendorsement]
Allowed Kinds:      [endorsement transaction]
```

**Note:** `--base-dir` can be provided in the config.yaml file itself. Below is a sample layout of a config file.

```yaml
base_dir: /tmp/
server:
  address:
  utility_address:
vaults:
  azure:
    ...
tezos:
  tz2***:
    log_payloads: true
    allow:
      block:
      endorsement:
      preendorsement:
      generic:
        - transaction
  tz3***:
    log_payloads: true
    allow:
      generic:
        - transaction
```

**Note:** after importing the key it is made active by adding it to the config file

## Octez Client
The `octez-client` is the official Octez CLI tool. This document shows how to configure a new account in `octez-client` that Signatory backs.

`octez-client` helps with verifying the setup and fills a need when operators of a baker require to transfer tokens out of their baking account to, for example, a hot wallet.

### Getting octez-client

Download the latest `octez-client` binary from the _Releases_ page at https://github.com/serokell/tezos-packaging 
Make sure to choose the appropriate binary for your operating system and architecture.

The `octez-client` is also included `octez-client` in the official Octez docker images.

### octez-client configuration

`octez-client` stores configuration in the directory `${HOME}/.octez-client` by default. 

The main configuration file for `octez-client` is `${HOME}/.octez-client/config`.

To display the configuration, run the command `octez-client config show`

If no configuration exists, you can have `octez-client` initialize a new configuration directory and file by running the command: 

```
octez-client config init --endpoint https://jakartanet.ecadinfra.com
```

You can specify the preferred RPC address of the Tezos network you wish to use. You can find a list of public RPC nodes here: https://tezostaquito.io/docs/rpc_nodes/

### octez-client listing and showing accounts

To list all accounts, `octez-client` has been configured.

- `octez-client list known addresses` Lists all addresses that are present in the `~/.octez-client` configuration 

To display all information about a specific account, including the secret or secret pointer.

- `octez-client show address ${alias} --show-secret` Displays all information about a given known address  

### Importing a remote signer account with `octez-client`

For `octez-client` to use a remote signer, octez-client needs to know the address of the remote signer service.

`octez-client` has a subcommand called `import secret key`, which allows users to import both actual secret key material and "import" a pointer to a remote signer that manages the secret.

Assuming you have a remote signer running on `http://localhost:6732/` and a key configured for `tz1M3kiQUMPcTseo72i1twdiV4iTY5yiGNSz`, you can then "import" a pointer to that secret into your `octez-client` configuration.

```
octez-client import secret key remote_signer_alias http://localhost:6732/tz1M3kiQUMPcTseo72i1twdiV4iTY5yiGNSz
```

You can then verify the details of this import by running the command:

```
$ octez-client show address remote_signer_alias --show-secret
Hash: tz1M3kiQUMPcTseo72i1twdiV4iTY5yiGNSz
Public Key: edpkuNyLH57vRp2dyzeDSg2G7AarZcp29DQnkQaXrSNdkRkAE4B1ZA
Secret Key: http://localhost:6732/tz1M3kiQUMPcTseo72i1twdiV4iTY5yiGNSz
```

Note that we passed the `--show-secret` flag. This flag displays the URL to the remote signer but not the secret. In this case, the secret is in the remote signer's custody.

### Test a signing request using `octez-client`

To sign arbitrary data using `octez-client,` run the command:

```
octez-client sign bytes 0x50deadbeef for octez_signer_local_key
```

If the remote signer allows signing operations with magic byte `0x05`, or "Michelson Data", the `octez-client` will output a Signature.

## Configuring octez-client to use Signatory for remote signing

Once the key is imported and made active, the value of the secret key in octez-client configuration is replaced with the key's URI in Signatory:

```bash
% octez-client import secret key import-p256 http://<signatory_host>:6732/tz3gxd1y7FdVJ81vzvuACcVjAc4ewXARQkLo
```
