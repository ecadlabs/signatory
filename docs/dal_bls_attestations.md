---
id: dal_bls_attestations
title: DAL & BLS Attestations
sidebar_label: DAL & BLS Attestations
---

# DAL Attestations: BLS vs Non-BLS Keys

:::warning Critical: Different Encoding for BLS Keys
**BLS keys (tz4) use a different attestation encoding than non-BLS keys (tz1/tz2/tz3).** The `attestation_with_dal` permission is **ONLY valid for tz1/tz2/tz3 keys**. BLS keys use tag 41 encoding which always decodes to `attestation`, regardless of DAL participation.

**New to operation encoding?** See the [Glossary](glossary.md) for detailed explanation of magic bytes vs operation tags with real examples.
:::

## BLS Keys (tz4) with DAL

### The Dual Signature Pattern

With **tz4 consensus + tz4 companion keys** and DAL enabled, when your baker has attestation rights AND DAL content is available:

- **Request 1**: Consensus key receives tag 41 bytes (magic byte `0x13`, operation tag `0x29`)
- **Request 2**: Companion key receives **identical** tag 41 bytes  
- Baker performs weighted BLS aggregation using DAL content (outside the signed bytes)
- Result sent to network

**Both keys receive identical bytes and decode to the same request type: `attestation`**

### BLS Mode Encoding (Tag 41)

BLS keys use a **simplified attestation encoding** that contains only:
- Level
- Round  
- Block payload hash

**The DAL content (`dal_content` bitset) is NOT included in the signed bytes.** It's used separately in the weighted BLS aggregation formula after both signatures are produced.

This is why both consensus and companion keys sign identical bytes - the DAL participation happens at the aggregation level, not the signing level.

## Why Companion Keys?

**Problem:** BLS signatures aggregate only when validators sign identical data. With DAL, each delegate attests to different slots, but we need efficient aggregation.

**Solution:** BLS mode encoding **strips DAL content from the signed bytes**.

**How it works:**

1. **Individual baker level**: 
   - Both consensus and companion keys sign **identical bytes** (tag 41: level + round + block_payload_hash)
   - DAL bitset is NOT in the signed bytes

2. **Network aggregation level**:
   - **Consensus signatures**: Standard BLS aggregation (all sign same data)
   - **Companion signatures**: Weighted BLS aggregation where DAL bitset is the weight
   - Uses the formula: `aggregate_weighted(signature, dal_bitset)` for each baker
   
This allows each baker to attest different DAL slots while maintaining BLS signature efficiency.

:::info BLS Mode Encoding
**Tag 41 (BLS mode)** encoding contains ONLY consensus data (level, round, block_payload_hash). The `dal_content` field is explicitly dropped during encoding and used separately in the aggregation formula. This is why both consensus and companion keys sign identical bytes and both decode to `"attestation"` in Signatory logs.
:::

## Signatory Configuration

### BLS Keys (tz4) - With or Without DAL

```yaml
tezos:
  # Manager key (tz1) - for operational transactions
  tz1YourManagerKey:
    log_payloads: true
    allow:
      generic:
        - reveal
        - delegation
        - transaction
        - stake

  # Consensus key (tz4)
  tz4YourConsensusKey:
    log_payloads: true
    allow:
      block:
      attestation:     # Tag 41 - used for all attestations
      preattestation:  # Tag 40

  # Companion key (tz4)
  tz4YourCompanionKey:
    log_payloads: true
    allow:
      attestation:     # Tag 41 - SAME as consensus key
      preattestation:  # Tag 40 - SAME as consensus key
```

**Important:** BLS keys use tag 41 encoding which **does not include** `attestation_with_dal`. Both consensus and companion keys receive identical tag 41 bytes and require the same permissions.

### Non-BLS Keys (tz1/tz2/tz3) - With DAL

```yaml
tezos:
  # tz1 manager/consensus key
  tz1YourBakerKey:
    log_payloads: true
    allow:
      block:
      attestation:          # Tag 21 (when DAL unavailable: node offline, syncing, or no shards)
      attestation_with_dal: # Tag 23 (when DAL content present and node operational)
      preattestation:       # Tag 20 (always needed)
```

**Important:** Non-BLS keys use tag 23 encoding which **includes the DAL bitset** in the signed bytes. You need both `attestation` (tag 21) and `attestation_with_dal` (tag 23) permissions because the baker will send different tags depending on DAL availability.

**Note:** tz1/tz2/tz3 keys can participate in DAL and earn DAL rewards, but typically attest with bitset 0 (no shard attestation capability). Full DAL shard attestation requires BLS keys (tz4) with consensus + companion key setup.

### Key Differences

| Key Type | Encoding | DAL in Bytes? | Permissions Needed |
|----------|----------|---------------|-------------------|
| **tz4** | Tag 41 (BLS mode) | ❌ No - stripped out | `attestation`, `preattestation` |
| **tz1/tz2/tz3** | Tag 21/23 | ✅ Yes - tag 23 includes bitset | `attestation`, `attestation_with_dal`, `preattestation` |

## Expected Log Behavior

### BLS Keys (tz4) with DAL

**With attestation rights + DAL content:**
```log
INFO Requesting signing operation  pkh=tz4Consensus... req=attestation level=12345
INFO Signed attestation successfully

INFO Requesting signing operation  pkh=tz4Companion... req=attestation level=12345
INFO Signed attestation successfully
```

**Result:** Two signatures, both show `req=attestation` (tag 41).

**With attestation rights, no DAL content:**
```log
INFO Requesting signing operation  pkh=tz4Consensus... req=attestation level=12345
INFO Signed attestation successfully
```

**Result:** One signature (consensus only).

### Non-BLS Keys (tz1/tz2/tz3) with DAL

**With attestation rights + DAL content:**
```log
INFO Requesting signing operation  pkh=tz1YourKey... req=attestation_with_dal level=12345
INFO Signed attestation_with_dal successfully
```

**Result:** One signature showing `req=attestation_with_dal` (tag 23).

**With attestation rights, no DAL content:**
```log
INFO Requesting signing operation  pkh=tz1YourKey... req=attestation level=12345
INFO Signed attestation successfully
```

**Result:** One signature showing `req=attestation` (tag 21).

## Troubleshooting

### "Companion tz4 key never signs"

**Check:**
1. Does baker command include `--dal-node` flag and both key aliases?
2. Is DAL node running and synced? `curl http://localhost:10732/level`
3. Is `attestation` permission in companion key policy? (NOT `attestation_with_dal`)
4. Verify attestation rights: `octez-client rpc get "/chains/main/blocks/head/helpers/attestation_rights?delegate=YOUR_PKH"`

**Remember:** Companion key only signs when baker has attestation rights **AND** DAL content is available.

### "Signatory rejects tz4 companion key: 'attestation_with_dal' not allowed"

**This is a configuration error.** BLS keys (tz4) don't use `attestation_with_dal`. Fix:

```yaml
tz4YourCompanionKey:
  allow:
    attestation:  # Correct - tz4 uses tag 41
    # attestation_with_dal:  # WRONG for tz4 - remove this
```

### "tz1 key with DAL: 'attestation_with_dal' not allowed"

**Missing permission.** Non-BLS keys need both:

```yaml
# tz1 manager/consensus key
tz1YourKey:
  allow:
    attestation:          # Tag 21 (when DAL unavailable: node offline, syncing, or no shards)
    attestation_with_dal: # Tag 23 (when DAL content present and node operational)
    preattestation:       # Tag 20 (always needed)
```

### "Not earning DAL rewards"

Check participation:
```bash
octez-client rpc get "/chains/main/blocks/head/context/delegates/YOUR_PKH/participation"
```

Look for `dal_attested_slots` > 0. If zero, verify DAL node sync and baker `--dal-node` flag.

## Configuration Summary

### BLS Keys (tz4)

**Signatory permissions for ANY tz4 key (consensus or companion):**
```yaml
tz4AnyKey:
  allow:
    attestation:     # Tag 41 encoding
    preattestation:  # Tag 40 encoding
```

**Do NOT use `attestation_with_dal` for tz4 keys** - it has no effect.

### Non-BLS Keys (tz1/tz2/tz3) with DAL

**Signatory permissions:**
```yaml
# tz1 manager/consensus key
tz1YourKey:
  allow:
    attestation:          # Tag 21 (when DAL unavailable: node offline, syncing, or no shards)
    attestation_with_dal: # Tag 23 (when DAL content present and node operational)
    preattestation:       # Tag 20 (always needed)
```

### Quick Setup (tz1 Manager + tz4 BLS Keys)

```bash
# Register and set keys
octez-client register key manager_tz1 as delegate
octez-client set consensus key for manager_tz1 to consensus_tz4
octez-client set companion key for manager_tz1 to companion_tz4

# Start baker with DAL
octez-baker run with local node ~/.tezos-node \
  --liquidity-baking-toggle-vote pass \
  --dal-node http://localhost:10732 \
  consensus_tz4 companion_tz4
```

---

**Protocol:** Tezos 023 (PsSeouLo) | **Tested:** Octez 23.2, Seoultestnet, Oct 2025

For full DAL node setup, see [Tezos DAL documentation](https://octez.tezos.com/docs/shell/dal_run.html).

