---
id: cli
title: CLI
---

# Key Import using signatory-client

To import a secret key, we will use the `signatory-cli` command.

## Generating key using tezos-client

```bash
% tezos-client gen keys import-p256 -s p256 --encrypted
Enter password to encrypt your key:
Confirm password:
```

```bash
% tezos-client list known addresses
import-p256: tz3gxd1y7FdVJ81vzvuACcVjAc4ewXARQkLo (encrypted sk known)
```

The encrypted private key can be obtained from the `.tezos-client/` directory

```bash
% cat ~/.tezos-client/secret_keys
[ { "name": "import-p256",
    "value":
      "encrypted:p2esk**********************************************************" }]
```

## Importing the generated key using signatory-cli

Private key can be imported into any of the backend vaults (except: AWS & ledger) using below command.
If you import an encrypted key, the `signatory-cli` command will prompt you for the password.

```bash
% ./signatory-cli import -c ./s.yaml_Azure --base-dir ./ --vault azure p2esk*****************
INFO[0000] Initializing vault                            vault=azure vault_name=azure
Enter Password: 
INFO[0002] Requesting import operation                   pkh=tz3gxd1y7FdVJ81vzvuACcVjAc4ewXARQkLo vault=Azure vault_name="https://forimport.vault.azure.net/"
INFO[0007] Successfully imported                         key_id="https://forimport.vault.azure.net/keys/signatory-imported-2CsWhgGqeRdkEiA0LFm3WyN5DxS/9d2266b388734ef0b14203e0943465d7" pkh=tz3gxd1y7FdVJ81vzvuACcVjAc4ewXARQkLo vault=Azure vault_name="https://forimport.vault.azure.net/"
```

If the import is successful, the `signatory-cli` will report the PKH (`tz3gxd1y7FdVJ81vzvuACcVjAc4ewXARQkLo` in above example) of your newly imported secret which in turn can be used in the config YAML to add the policies.

**Note:** PKH from Signatory and the PKH from `tezos-client list known addresess` command must be same.

## Verifying import operation using list command

Import operation can be verified in the vault or using the below list command.

```bash
 % ./signatory-cli list -c ./s.yaml_Azure --base-dir ./
INFO[0000] Initializing vault                            vault=azure vault_name=azure

Public Key Hash:    tz2VamQJcdSBtXghHijT9VsqDzC86Hq1HDpB
Vault:              Azure
ID:                 https://forimport.vault.azure.net/keys/imp-key/58441908018943889c0370fe9c228269
Active:             true
Allowed Operations: [block endorsement generic]
Allowed Kinds:      [endorsement transaction]
```
