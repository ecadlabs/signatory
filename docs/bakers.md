---
id: bakers
title: Tezos Bakers
---

# How to use Signatory with a Tezos Baker

A Tezos baker can use Signatory as a remote signer with keys stored in a local file (dev only), a Ledger device, or enterprise vaults (AWS KMS, GCP KMS, Azure Key Vault, YubiHSM, etc.). This guide shows practical setups for **Local Secret** and **Ledger**; other vaults follow the same pattern.

## Bakers on Tezos Networks

**Prerequisites**

- A working `octez-client`
- A Tezos node RPC endpoint (e.g. `http://localhost:8732`)
- The baker's public key hash (PKH), e.g. `tz1...` (we use `baking_key` as the alias in examples)
- The network’s current protocol (for selecting the correct baker binary)

**Verify the node is ready**

```bash
# Node bootstrap status
curl -s http://localhost:8732/chains/main/is_bootstrapped

# Or via the client (also ensures your client points at the right node)
octez-client --endpoint http://localhost:8732 bootstrapped
````

**List known addresses**

```bash
octez-client list known addresses
```

**Show the baker address**

```bash
octez-client show address baking_key
```

**Fund and register the delegate**

Wait until the node is bootstrapped, then fund the implicit account (use a faucet on testnets). Check balance:

```bash
octez-client get balance for baking_key
```

Register as a delegate (optionally set a consensus key):

```bash
# register the implicit account as a delegate
octez-client register key baking_key as delegate

# OR register baking_key as a delegate but use a separate consensus key
octez-client register key baking_key as delegate with consensus key consensus_key
```

**Check rights**

Modern terminology uses **baking** and **attesting** (formerly "endorsing"). The RPC to query attesting rights is `attestation_rights`. (The older `endorsing_rights` was deprecated.)

```bash
# Baking rights (you may need to provide a future cycle)
octez-client rpc get /chains/main/blocks/head/helpers/baking_rights?cycle=<cycle>\&delegate=<pkh>

# Attestation rights (preferred modern name)
octez-client rpc get /chains/main/blocks/head/helpers/attestation_rights?cycle=<cycle>\&delegate=<pkh>
```

**Start the baker**

```bash
# Use the correct protocol suffix (example placeholder <PROTO_HASH>)
octez-baker-<PROTO_HASH> run with local node ~/.tezos-node --liquidity-baking-toggle-vote pass
```

---

## Signatory

Clone and build Signatory (or use Docker):

```bash
git clone https://github.com/ecadlabs/signatory.git
cd signatory
make signatory
make signatory-cli
```



### 1) Local Secret (dev/test only)

> **Warning:** File-based secrets are for development/prototyping only. Don't use in production.

Create `/etc/secret.json` with the baker’s secret **(example only; never publish real keys):**

```json
[
  {
    "name": "tz1YourBakerAddress",
    "value": "unencrypted:edskYourDevOnlySecretKey"
  }
]
```

Create `local_secret.yaml`:

```yaml
server:
  address: :6732
  utility_address: :9583

vaults:
  local_secret:
    driver: file
    config:
      file: /etc/secret.json

tezos:
  tz1YourBakerAddress:
    log_payloads: true
    allow:
      block:
      # For Tenderbake-era naming; Signatory also supports newer terms (see notes below)
      endorsement:
      preendorsement:
      generic:
        - reveal
        - delegation
        - transaction
```

Start Signatory:

```bash
signatory serve -c local_secret.yaml
```

Test it:

```bash
# Get public key via remote signer HTTP interface
curl -s localhost:6732/keys/tz1YourBakerAddress
# -> {"public_key":"edpk..."}
```

Point `octez-client` at Signatory (remote signer):

```bash
octez-client import secret key baking_key http://localhost:6732/tz1YourBakerAddress --force
cat ~/.tezos-client/secret_keys
# [{"name":"baking_key","value":"http://localhost:6732/tz1YourBakerAddress"}]
```

(Octez's remote signer uses HTTP endpoints like `GET/POST /keys/<pkh>` under the hood.)

Try an operation and observe Signatory logs:

```bash
octez-client transfer 10 from baking_key to tz1RecipientAddress
```

### 2) Ledger Devices

1. Ensure your OS can access the Ledger (udev rules etc.).
2. Confirm the Ledger Tezos Baking app is running; list connected devices:

```bash
octez-client list connected ledgers
```

Import the key from Ledger to `octez-client` with your chosen curve/path (examples):

```bash
# Choose one path/curve:
octez-client import secret key ledger_michael "ledger://<ledger-id>/bip25519/0h/0h"
# or
octez-client import secret key ledger_michael "ledger://<ledger-id>/ed25519/0h/0h"
# or
octez-client import secret key ledger_michael "ledger://<ledger-id>/secp256k1/0h/0h"
# or
octez-client import secret key ledger_michael "ledger://<ledger-id>/P-256/0h/0h"
```



Authorize baking on the Ledger and set up baking HWMs in Signatory:

```bash
# Find your device id
signatory-cli ledger list -c ledger.yaml

# Set up baking for a bip32-ed25519 path (Tezos purpose 44', coin 1729')
signatory-cli ledger setup-baking -c ledger.yaml -d <device_id> "bip32-ed25519/44'/1729'/0'/0'"
```



Create `ledger.yaml`:

```yaml
server:
  address: :6732
  utility_address: :9583

vaults:
  ledger:
    driver: ledger
    config:
      id: <device_hex_id>
      keys:
        - "bip32-ed25519/44'/1729'/0'/0'"
      close_after: 600s  # optional: close device after inactivity

tezos:
  tz1LedgerBakerAddress:
    log_payloads: true
    allow:
      block:
      endorsement:
      preendorsement:
      generic:
        - transaction
        - reveal
        - delegation
```

Verify the key is active:

```bash
signatory-cli list -c ledger.yaml
# Shows PKH, Vault: Ledger, Active: true, Allowed Operations...
```



Start your baker normally. You should see (pre)attestations in baker logs and the corresponding signing requests in Signatory.

---

## Other Vault Types

All enterprise vaults follow the same pattern:

1. **Configure the vault driver** under `vaults:` (KMS/HSM connection settings)
2. **List/activate keys** and copy the PKH from `signatory-cli list` into the `tezos:` section
3. **Import the key endpoint** into `octez-client` via `http://<signatory>:6732/<pkh>`
4. **Bake** as usual

See the official [Signatory documentation](https://signatory.io/docs/) for AWS/GCP/Azure/YubiHSM examples.

### Vault Selection Guidelines

* **Local Secret:** dev & testing only
* **Ledger:** individuals/small ops; good security
* **Cloud KMS / YubiHSM:** enterprise setups & HSM-backed keys

---

## Baking with DAL (Data Availability Layer)

To attest DAL data, run a DAL node alongside your L1 node and tell the baker to use it.

1. Initialize and run a DAL node:

```bash
# Initialize (use your baker PKH for --attester-profiles)
octez-dal-node config init --endpoint http://127.0.0.1:8732 --attester-profiles="$MY_ADDRESS" --data-dir ~/.tezos-dal-node

# Run
octez-dal-node run --data-dir ~/.tezos-dal-node
```

2. Start the baker and point it at the DAL node:

```bash
octez-baker-<PROTO_HASH> run with local node ~/.tezos-node \
  --dal-node http://127.0.0.1:10732 \
  --liquidity-baking-toggle-vote pass
```



3. Rights & monitoring:

```bash
# Check attestation rights
octez-client rpc get "/chains/main/blocks/head/helpers/attestation_rights?delegate=$MY_ADDRESS&cycle=<current-cycle>"
```

> **Operation names.** In modern Octez, "endorsements" are "attestations" and there is a dedicated **`attestation_with_dal`** operation for DAL data. Make sure your Signatory version supports these newer kinds.

**Signatory allow-list example with DAL:**

```yaml
tezos:
  tz1YourBakerAddress:
    log_payloads: true
    allow:
      block:
      attestation:
      preattestation:
      attestation_with_dal:
      generic:
        - transaction
        - reveal
        - delegation
```

> If you're on an older Signatory config/example that still uses `endorsement`/`preendorsement`, keep those; newer releases recognize `attestation`/`preattestation` and `attestation_with_dal`.

---

## Vault-Agnostic Signatory CLI

Useful commands that work across vaults (where supported):

```bash
# List all keys Signatory can see (and whether each is Active in config)
signatory-cli list -c signatory.yaml

# Validate configuration without starting the server
signatory serve -c signatory.yaml --dry-run
```



**Remote signer health & introspection**

```bash
# Public key for a PKH
curl localhost:6732/keys/tz1...

# Health endpoint
curl localhost:9583/healthz

# Authorized client keys (if you enable client auth)
curl localhost:6732/authorized_keys
```



```


