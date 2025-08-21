---
id: bakers
title: Tezos Bakers
---

# How to use Signatory with a Tezos Baker

A Tezos baker can use Signatory as a remote signer with keys stored securely in enterprise vaults (AWS KMS, GCP KMS, Azure Key Vault, YubiHSM, etc.) or locally in files for development purposes only. This guide shows a **Local Secret** setup for development; production deployments should use proper vault implementations.

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

**Get Signatory using Docker (recommended):**

```bash
# Pull the latest Signatory Docker image
docker pull ecadlabs/signatory

# Or use a specific version
docker pull ecadlabs/signatory:v1.2.3
```

**Or download prebuilt binaries:**

Download the latest release binaries from the [Signatory GitHub Releases page](https://github.com/ecadlabs/signatory/releases). Extract and install:

```bash
# Example for Linux x64 (check releases page for your platform)
wget https://github.com/ecadlabs/signatory/releases/download/v1.2.3/signatory_1.2.3_linux_amd64.tar.gz
tar -xzf signatory_1.2.3_linux_amd64.tar.gz
sudo mv signatory* /usr/local/bin/
```



### Local Secret Vault (Development Only)

:::caution Development Only Warning
File-based secrets are **ONLY** for development and testing. **Never use in production.** For production deployments, use proper vault solutions like AWS KMS, Azure Key Vault, GCP Key Management Service, or YubiHSM for secure key storage and management.
:::

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
# Using Docker (recommended)
docker run -d --name signatory \
  -p 6732:6732 -p 9583:9583 \
  -v $(pwd)/local_secret.yaml:/local_secret.yaml \
  -v /etc/secret.json:/etc/secret.json \
  ecadlabs/signatory serve -c /local_secret.yaml

# Or if using prebuilt binary
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

---

## Other Vault Types

All enterprise vaults follow the same pattern:

1. **Configure the vault driver** under `vaults:` (KMS/HSM connection settings)
2. **List/activate keys** and copy the PKH from `signatory-cli list` into the `tezos:` section
3. **Import the key endpoint** into `octez-client` via `http://<signatory>:6732/<pkh>`
4. **Bake** as usual

See the official [Signatory documentation](https://signatory.io/docs/) for AWS/GCP/Azure/YubiHSM examples.

### Vault Selection Guidelines

* **Local Secret:** Development and testing only - **never for production**
* **Cloud KMS (AWS/GCP/Azure):** Enterprise production deployments with cloud HSM backing
* **YubiHSM:** On-premises hardware security module for enterprise setups
* **Other options:** See [Signatory vault documentation](https://signatory.io/docs/) for additional vault types

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

:::note Terminology
Signatory supports both old (`endorsement`/`preendorsement`) and modern (`attestation`/`preattestation`) terminology in policy configuration. Both work identically, but we recommend using the modern terms to match current Tezos protocol terminology.
:::

**DAL Setup Overview**

To participate in DAL attestations:

1. **Run a DAL node** alongside your Tezos node
2. **Configure your baker** to use the DAL node (`--dal-node` flag)
3. **Update Signatory policy** to allow `attestation_with_dal` operations

:::warning Important
Without `attestation_with_dal` in your Signatory policy, DAL attestation requests will be rejected, and you'll miss those rewards.
:::

**Consensus Keys and DAL**

While consensus keys are not strictly required for DAL operations, **using consensus keys is considered current best practice** for production baking setups. Consensus keys provide operational flexibility and security benefits by separating the baker's identity (manager key) from the key used for consensus operations (baking, attesting).

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


