---
id: glossary
title: Glossary
sidebar_label: Glossary
---

# Signatory Glossary

## Terms

### BLS Mode

Optimized operation encoding for BLS keys (tz4). Uses tag 41 (attestation) or tag 40 (preattestation) with simplified structure containing only level, round, and block_payload_hash. DAL content is not included in signed bytes.

### Companion Key

A secondary BLS key (tz4) used for DAL participation. Signs only when baker has attestation rights AND DAL content is available. Receives identical bytes as consensus key (tag 41).

### Consensus Key

Primary signing key for block baking and attestations. Signs blocks when baker has baking rights, and signs attestations when baker has attestation rights.

### DAL (Data Availability Layer)

Tezos protocol feature enabling high-bandwidth data distribution outside L1 blocks. Bakers participating earn additional rewards (~10% of participation rewards). See [DAL & BLS Attestations](dal_bls_attestations.md).

### Magic Byte

First byte of a signing request identifying the operation type. Values: `0x13` = attestation, `0x12` = preattestation, `0x11` = block, `0x03` = generic operation. In Tezos code this is called the "watermark" parameter - different from Signatory's watermark feature.

### Operation Tag

Byte at position 37 (after ChainID + Branch) identifying the operation encoding variant. For attestations: tag 21 = `Attestation`, tag 23 = `AttestationWithDAL` (tz1/tz2/tz3 only), tag 41 = `BLSModeAttestation` (tz4 only).

### Request Kind

String label Signatory uses for policy enforcement after decoding bytes. Values: `"attestation"`, `"attestation_with_dal"`, `"preattestation"`, `"block"`, `"generic"`. Visible in logs as `request=attestation`. This is what you configure in the `allow:` section.

### Watermark (Signatory Feature)

Signatory's double-signing prevention system tracking highest level/round signed for each key. Prevents slashable double-signing. Backends: file (default), memory (testing), AWS DynamoDB (distributed). See [Watermarks documentation](watermarks.md). Different from Tezos protocol's "watermark" parameter (magic byte).

## Examples from Actual Signatory Logs

**tz4 BLS attestation:**
```
raw=137a06a770...29...
     ↑         ↑   ↑
     |         |   Tag 0x29 (41 decimal) = BLSModeAttestation
     |         ChainID + Branch (36 bytes)
     Magic byte 0x13 (attestation)

Decodes to: request=attestation
```

**tz1 DAL attestation:**
```
raw=1377fe09b1...17...
     ↑         ↑   ↑
     |         |   Tag 0x17 (23 decimal) = AttestationWithDAL
     |         ChainID + Branch (36 bytes)
     Magic byte 0x13 (attestation)

Decodes to: request=attestation_with_dal
```

## Tag to Permission Mapping

| Tag | Decoded Type | Request Kind | Valid For |
|-----|--------------|--------------|-----------|
| 21 | Attestation | `"attestation"` | tz1/tz2/tz3 |
| 23 | AttestationWithDAL | `"attestation_with_dal"` | tz1/tz2/tz3 only |
| 41 | BLSModeAttestation | `"attestation"` | tz4 only |

