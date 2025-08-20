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
# (first create the consensus key if it doesn't exist)
octez-client register key baking_key as delegate with consensus key consensus_key
```

**Stake funds for baking:**

After registration, you must stake funds to participate in baking:

```bash
# Stake tez for baking (adjust amount as needed)
octez-client stake 10000 for baking_key
```

**Check rights**

Modern terminology uses **baking** and **attesting** (formerly "endorsing"). The RPC to query attesting rights is `attestation_rights`. (The older `endorsing_rights` was deprecated.)

```bash
# Baking rights (you may need to provide a future cycle)
octez-client rpc get "/chains/main/blocks/head/helpers/baking_rights?cycle=<cycle>&delegate=<pkh>"

# Attestation rights (preferred modern name)
octez-client rpc get "/chains/main/blocks/head/helpers/attestation_rights?cycle=<cycle>&delegate=<pkh>"
```

**Terminology Note:** Tezos protocol terminology evolved from "endorsement" to "attestation" (and "preendorsement" to "preattestation"). Signatory policy configuration supports both terminologies, but this guide uses the modern terms to stay current with protocol naming.

**Start the baker**

```bash
# Modern agnostic baker (automatically detects protocol)
octez-baker run with local node ~/.tezos-node --liquidity-baking-toggle-vote pass
```

---

## Signatory

Clone and build Signatory (or use Docker):

```bash
git clone https://github.com/ecadlabs/signatory.git
cd signatory
make all
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
      attestation:        # Modern terminology (was "endorsement") 
      preattestation:     # Modern terminology (was "preendorsement")
      generic:
        - reveal
        - delegation
        - transaction
        - stake
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
      attestation:        # Modern terminology (was "endorsement")
      preattestation:     # Modern terminology (was "preendorsement") 
      generic:
        - transaction
        - reveal
        - delegation
        - stake
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

**Critical Signatory Configuration for DAL**

If your baker participates in DAL attestations, you **must** add `attestation_with_dal` to your Signatory policy. This is a separate operation type from regular attestations.

```yaml
tezos:
  tz1YourBakerAddress:
    log_payloads: true
    allow:
      block:              # Standard block baking
      attestation:        # Standard attestations
      preattestation:     # Pre-attestations  
      attestation_with_dal: # ✨ Required for DAL attestations
      generic:
        - transaction
        - reveal
        - delegation
        - stake
```

> **Note on Terminology:** Signatory supports both old (`endorsement`/`preendorsement`) and modern (`attestation`/`preattestation`) terminology in policy configuration. Both work identically, but we recommend using the modern terms to match current Tezos protocol terminology.

**DAL Setup Overview**

To participate in DAL attestations:

1. **Run a DAL node** alongside your Tezos node
2. **Configure your baker** to use the DAL node (`--dal-node` flag)
3. **Update Signatory policy** to allow `attestation_with_dal` operations

> **Important:** Without `attestation_with_dal` in your Signatory policy, DAL attestation requests will be rejected, and you'll miss those rewards.

**Further Reading**

The details of running DAL nodes and collecting DAL attestation rewards are outside the scope of this Signatory guide. For comprehensive information:

- **[Tezos DAL Architecture](https://docs.tezos.com/architecture/data-availability-layer)** - explains what the DAL is, how bakers run with a DAL attester node, and how DAL rewards work (10% of participation rewards starting in Rio; you must attest ≥64% of assigned shards; "trap shard" denouncements can forfeit the cycle's DAL rewards)
- **[DAL Node Setup Guide](https://octez.tezos.com/docs/shell/dal_run.html)** - step-by-step setup guide for the DAL attester node

---

## Protocol-Agnostic Baker Commands

Recent Octez versions include protocol-agnostic baker commands that automatically detect the current network protocol, eliminating the need to specify protocol-specific binary names.

**Modern Agnostic Commands:**

```bash
# Use the agnostic baker (automatically detects protocol)
octez-baker run with local node ~/.tezos-node --liquidity-baking-toggle-vote pass

# The agnostic baker replaces protocol-specific commands like:
# octez-baker-PsQuebec, octez-baker-PsNairob, octez-baker-alpha, etc.
```

**Agnostic Accuser:**

```bash
# Use the agnostic accuser 
octez-accuser run

# No need for protocol-specific accusers anymore
```

**Benefits:**

- **Automatic protocol detection**: No need to know current protocol hash
- **Seamless upgrades**: Works across protocol transitions
- **Simplified operations**: One command works on any network
- **Future-proof**: Commands remain valid as protocols evolve

**Migration Note:**

If you're using older protocol-specific commands, you can migrate to agnostic ones without changing your Signatory configuration. The remote signer interface remains the same.

For more details, see the [Tezos agnostic baker documentation](https://gitlab.com/tezos/tezos/-/blob/master/src/bin_agnostic_baker/README.md).


