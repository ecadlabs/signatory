---
id: proof_of_possession
title: Proof of Possession (POP)
sidebar_label: Proof of Possession
---

## Overview

Proof of Possession (POP) is a cryptographic proof that demonstrates ownership of a private key by creating a signature over the public key itself. In Tezos, POP is specifically required for BLS keys (tz4 addresses) during initial key reveal operations and certain key management operations.

**Important:** POP is disabled by default for all keys and must be explicitly enabled per-key in the configuration. This is a security best practice—POP should only be enabled temporarily during setup operations, then disabled for production signing.

## When POP is Required

### Initial BLS Key Reveals
When a tz4 address is used for the first time, the Tezos protocol requires a reveal operation that includes a Proof of Possession. This proves that the entity revealing the key actually controls the private key.

**Use cases:**
- First transaction from a new tz4 address
- Initial setup of a tz4 baker account

### Consensus Key Updates
When updating a delegate's consensus key to a tz4 address, POP is required to prove control of the new consensus key.

**Use cases:**
- Switching from tz1/tz2/tz3 consensus key to tz4
- Updating to a new tz4 consensus key

### Companion Key Registration (DAL)
When registering a tz4 companion key for Data Availability Layer (DAL) participation, POP is required.

**Use cases:**
- Registering a tz4 key as a DAL companion key
- DAL attestation setup

### BLS Multisig Setup
Some BLS multisig configurations may require POP for each participant key during setup.

## When POP is NOT Needed

### Regular Signing Operations
Once a key has been revealed and is in normal operation, POP is not required for:
- Block signing
- Attestations (endorsements)
- Preattestations (preendorsements)
- Regular transactions
- Smart contract interactions
- Delegation operations

### After Initial Reveal
After successfully completing the initial reveal operation with POP, subsequent operations from the same tz4 address do not require POP.

### Non-BLS Keys
Keys of type tz1 (Ed25519), tz2 (Secp256k1), and tz3 (P256) never require Proof of Possession. If you attempt to enable POP for these key types, Signatory will log a warning and ignore the setting.

## POP Lifecycle & Operational Patterns

### Pattern 1: Initial Setup (Recommended)

This is the recommended pattern for setting up a new tz4 key for production use:

**Step 1: Enable POP for reveal**
```yaml
tezos:
  tz4JtjLv1AvUdnvXkG9mBBmLgcwVBV2FoPBK:
    allow_proof_of_possession: true
    allow:
      generic:
        - reveal
```

**Step 2: Perform reveal with octez-client**
```sh
octez-client reveal key for tz4JtjLv1AvUdnvXkG9mBBmLgcwVBV2FoPBK
```

**Step 3: Disable POP and configure for production**
```yaml
tezos:
  tz4JtjLv1AvUdnvXkG9mBBmLgcwVBV2FoPBK:
    allow_proof_of_possession: false  # or remove this line
    allow:
      block:
      attestation:
      preattestation:
      generic:
        - transaction
        - delegation
```

**Step 4: Restart Signatory**
```sh
systemctl restart signatory
```

The key is now ready for production signing operations with POP disabled.

### Pattern 2: Consensus Key Update

When updating a delegate's consensus key to tz4:

**Step 1: Configure the new tz4 consensus key**
```yaml
tezos:
  # Existing delegate key
  tz1LggX2HUdvJ1tF4Fvv8fjsrzLeW4Jr9t2Q:
    allow:
      generic:
        - update_consensus_key

  # New tz4 consensus key
  tz4NewConsensusKeyHash:
    allow_proof_of_possession: true
    allow:
      block:
      attestation:
      preattestation:
```

**Step 2: Update consensus key**
```sh
octez-client set consensus key for tz1LggX2HUdvJ1tF4Fvv8fjsrzLeW4Jr9t2Q to tz4NewConsensusKeyHash
```

**Step 3: Disable POP after successful update**
```yaml
tezos:
  tz4NewConsensusKeyHash:
    allow_proof_of_possession: false  # Disable after update
    allow:
      block:
      attestation:
      preattestation:
```

### Pattern 3: DAL Companion Key

When registering a tz4 companion key for DAL:

```yaml
tezos:
  # Main baker key (tz1/tz2/tz3)
  tz1BakerAddress:
    allow:
      block:
      attestation:
      attestation_with_dal:  # tz1/tz2/tz3 keys use this for DAL
      generic:
        - set_companion_key

  # DAL companion key (tz4)
  tz4CompanionKeyHash:
    allow_proof_of_possession: true  # Enable for registration
    allow:
      attestation:  # tz4 keys use 'attestation' only, NOT 'attestation_with_dal'
```

After successful registration, disable POP:

```yaml
  tz4CompanionKeyHash:
    allow_proof_of_possession: false
    allow:
      attestation:  # tz4 keys use 'attestation' only, NOT 'attestation_with_dal'
```

### Pattern 4: Multisig Setup

For BLS multisig scenarios where multiple keys need POP enabled:

```yaml
tezos:
  # Multisig participant 1
  tz4Participant1Hash:
    allow_proof_of_possession: true
    allow:
      generic:
        - transaction  # multisig operations

  # Multisig participant 2
  tz4Participant2Hash:
    allow_proof_of_possession: true
    allow:
      generic:
        - transaction
```

**Note:** Some multisig configurations may require POP to remain enabled permanently. Check your specific multisig contract requirements.

### Pattern 5: Mixed Deployment

In production environments with multiple keys at different lifecycle stages:

```yaml
tezos:
  # Production baker - tz4 already revealed
  tz4ProductionBaker1:
    allow_proof_of_possession: false  # POP disabled for production
    allow:
      block:
      attestation:
      preattestation:

  # Production baker - tz1 key (POP not applicable)
  tz1ProductionBaker2:
    allow:
      block:
      attestation:
      preattestation:

  # New key being set up - temporary POP enabled
  tz4NewKeyBeingSetup:
    allow_proof_of_possession: true  # Temporary - will disable after reveal
    allow:
      generic:
        - reveal
```

## Security Considerations

### Why POP is Disabled by Default

Proof of Possession is disabled by default for several security reasons:

1. **Principle of Least Privilege:** Keys should only have the minimum necessary permissions for their current operational state.

2. **Attack Surface Reduction:** Enabling POP exposes an additional signing endpoint that is not needed for normal operations.

3. **Operational Clarity:** Explicit enablement ensures operators consciously decide when POP is needed, preventing accidental exposure.

### What Information POP Reveals

When a Proof of Possession request is served:
- The public key is revealed (if not already public)
- Confirms that Signatory has access to the private key
- Demonstrates the key is currently active and operational

### Potential Risks

**Key Enumeration:**
- Enabled POP endpoints can be probed to discover which keys are configured and active
- Attackers could identify high-value signing infrastructure

**Denial of Service:**
- POP generation consumes computational resources
- Repeated POP requests could be used in DoS attacks
- Some HSM backends may have rate limits or billing implications

**Configuration Drift:**
- Keys left with POP enabled indefinitely increase attack surface
- Forgotten POP settings can lead to security vulnerabilities

### Best Practices

1. **Enable Temporarily:** Only enable POP when needed for specific operations, then disable it immediately after.

2. **Per-Key Control:** Use per-key configuration rather than global settings. This ensures fine-grained control and reduces the blast radius of misconfigurations.

3. **Audit Configuration:** Regularly review your Signatory configuration to ensure POP is not enabled unnecessarily.

4. **Monitoring:** Set up alerts for POP requests in production environments—they should be rare events.

5. **Documentation:** Document when and why POP was enabled for each key, and track when it was disabled.

6. **Separation of Duties:** Consider using separate Signatory instances for setup operations (with POP) and production signing (without POP).

### Why Per-Key Control is Superior

Signatory implements per-key POP control rather than global control because:

- **Isolation:** A compromised configuration for one key doesn't affect others
- **Flexibility:** Different keys can be at different lifecycle stages simultaneously
- **Auditability:** Clear configuration shows exactly which keys have POP enabled
- **Safety:** Impossible to accidentally enable POP globally for all production keys
- **Compliance:** Easier to demonstrate security controls in regulated environments

## Troubleshooting Guide

### Error: "proof of possession is not allowed"

**Symptom:**
```
ERROR Proof of possession is not allowed. Proof of possession is required for key reveals,
consensus key updates, and companion key registration. To enable, set
'allow_proof_of_possession: true' in the config for this key.
```

**Cause:**
You're attempting a reveal or key management operation that requires POP, but it's disabled for this key.

**Solution:**
Add `allow_proof_of_possession: true` to the key's configuration:

```yaml
tezos:
  tz4YourKeyHash:
    allow_proof_of_possession: true
    allow:
      generic:
        - reveal  # or other operations you need
```

Then restart Signatory and retry the operation.

### Error/Warning: "proof of possession is not supported"

**Symptoms:**
```
ERROR proof of possession is not supported
```
or
```
WARN proof of possession is not supported for tz1YourKeyHash
```

**Cause 1: Non-BLS Key Type**

POP is only supported for BLS keys (tz4). If you're seeing this error/warning with a tz1, tz2, or tz3 key, POP is not applicable for that key type.

**Solution:**
Remove `allow_proof_of_possession` from the configuration for non-tz4 keys:

```yaml
tezos:
  tz1YourKeyHash:
    # Remove or comment out this line
    # allow_proof_of_possession: true
    allow:
      block:
      attestation:
```

**Cause 2: Vault Backend Limitation**

Some vault backends may not support the POP operation for BLS keys.

**Solution:**
- Check your vault backend's documentation
- Verify the vault backend supports BLS keys and POP signatures
- Consider using a different vault backend that supports POP

## Integration with Octez

### octez-client Commands That Trigger POP

The following `octez-client` commands will trigger POP requests to Signatory for tz4 keys:

1. **reveal key for \<address\>**
   - Initial key reveal for a tz4 address
   - Requires `allow_proof_of_possession: true`

2. **set consensus key for \<delegate\> to \<tz4_key\>**
   - Updates a delegate's consensus key to a tz4 key
   - Requires `allow_proof_of_possession: true` for the tz4 key

3. **register dal companion for \<delegate\> as \<tz4_key\>**
   - Registers a tz4 companion key for DAL participation
   - Requires `allow_proof_of_possession: true` for the tz4 key

## Configuration Reference

### YAML Configuration

```yaml
tezos:
  <public_key_hash>:
    allow_proof_of_possession: <true|false>  # Default: false
    # ... other policy settings
```

### Parameters

**allow_proof_of_possession** (boolean, optional, default: `false`)
- Controls whether Signatory will respond to Proof of Possession requests for this key
- `true`: POP requests are allowed (required for reveals and key management)
- `false` or omitted: POP requests are denied (production signing mode)
- Only effective for BLS keys (tz4); ignored for other key types

### Complete Example

```yaml
server:
  address: :6732
  utility_address: :9583

vaults:
  local_file:
    driver: file
    config:
      file: /etc/signatory/secret.json

watermark:
  driver: file

tezos:
  # Production tz4 baker (POP disabled)
  tz4ProductionBaker:
    allow_proof_of_possession: false
    log_payloads: true
    allow:
      block:
      attestation:
      preattestation:
      generic:
        - transaction
        - delegation

  # New tz4 key being set up (POP temporarily enabled)
  tz4NewKey:
    allow_proof_of_possession: true
    log_payloads: true
    allow:
      generic:
        - reveal

  # Regular tz1 key (POP not applicable)
  tz1RegularKey:
    log_payloads: true
    allow:
      block:
      attestation:
      preattestation:
      generic:
        - transaction
        - reveal
        - delegation
```

## See Also

- [Bakers Guide](bakers.md) - Configuration for baker operations
- [Watermarks](watermarks.md) - Preventing double-signing
- [Getting Started](start.md) - Basic Signatory setup
- [CLI Documentation](cli.md) - Command-line tools

