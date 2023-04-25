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

A private key can be imported into any of the backend vaults (except: AWS, file & ledger) using the below command.
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

## Configuring octez-client to use Signatory for remote signing

Once the key is imported and made active, the value of the secret key in octez-client configuration is replaced with the key's URI in Signatory:

```bash
% octez-client import secret key import-p256 http://<signatory_host>:6732/tz3gxd1y7FdVJ81vzvuACcVjAc4ewXARQkLo
```
