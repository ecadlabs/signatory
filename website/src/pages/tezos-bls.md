---
title: Signatory for Tezos BLS (tz4)
description: Signatory is a protocol-aware Tezos remote signer with first-class BLS / tz4 support, running in AWS Nitro Enclaves and Google Confidential Space. Built for institutional bakers, exchanges, custodians, and validators-at-scale migrating to BLS consensus keys on Tezos.
---

# Signatory for Tezos BLS

**The remote signer for tz4 keys that need to live in a cloud-grade trusted execution environment, with policy, watermarks, and audit built in.**

Tezos consensus supports BLS12-381 via tz4 keys, introduced in the Seoul protocol and carried forward in every protocol since. Bakers opt in by registering a tz4 consensus key; the active committee runs mixed, with tz1 / tz2 / tz3 and tz4 delegates side by side while the ecosystem migrates. If you're planning that migration and your keys belong in cloud infrastructure, Signatory is built for it.

Signatory is built and maintained by ECAD Labs, the team behind Taquito and the Go BLS12-381 bindings the Tezos ecosystem runs on.

---

## Is this the right signer for you?

**Use Signatory for tz4 if any of these apply:**

- You bake from cloud infrastructure (AWS, GCP) and your ops model assumes keys live with the workload.
- You manage more than a handful of keys: multiple delegates, consensus and companion keys for DAL, application keys for transactions and originations.
- You have compliance requirements: single-tenant HSM-class isolation, audit trails, policy enforcement, SOC2-adjacent controls.
- You run institutional infrastructure: exchange, custodian, validator-at-scale, oracle, or treasury signer.
- You need application signing alongside consensus signing, not just consensus.

**If home baking is your thing**, whether that's a weekend project, learning the protocol hands-on, or running a single delegate on your own terms, the new generation of dedicated Raspberry Pi BLS signers from the Tezos ecosystem (Nomadic Labs' RPI BLS Signer, TezSign, Russignol) is likely a better fit. They're purpose-built for exactly that use case. Signatory is aimed at operators who need the heavier machinery described below, and we'd rather be upfront about where each tool shines than oversell.

---

## What Signatory does for BLS

Tezos-native tz4 signing over the standard Tezos remote signer protocol. Your baker talks to Signatory exactly the way it talks to any Tezos remote signer. Signatory handles the BLS-specific behavior underneath:

- **Tag 41 consensus attestations**, the BLS-mode attestation encoding introduced in Seoul. The signed payload omits the slot field so all delegates sign identical bytes, which is what lets the protocol aggregate BLS attestations on-chain via the `Attestations_aggregate` operation.
- **Optional DAL companion key support.** For tz4 bakers who want to participate in DAL attestations and earn the associated rewards, Signatory supports the companion key pattern: a second tz4 key registered via `Update_companion_key` and managed alongside the consensus key under one configuration. See [DAL & BLS Attestations](/docs/dal_bls_attestations).
- **Proof of Possession (PoP)** for BLS key reveals, consensus key updates, and companion key registration. Enable per-key during setup, disable after. See [Proof of Possession](/docs/proof_of_possession).
- **Full policy engine.** The same per-operation allowlist, watermark enforcement, JWT-authenticated control plane, and Prometheus metrics you use for tz1 / tz2 / tz3 keys apply unchanged to tz4.

---

## Backends for tz4 signing

Being direct: the major cloud KMS products (AWS KMS, Azure Key Vault, Google Cloud KMS, HashiCorp Vault Transit) **do not support BLS12-381 signing today**. Traditional HSMs exposed via PKCS#11 and YubiHSM2 likewise don't. This is a limitation of the underlying services, not of Signatory, and it holds across the industry, not just in Tezos.

What does work, and what Signatory supports for tz4:

| Backend | tz4 signing | Key generation | Typical role |
|---|---|---|---|
| **AWS Nitro Enclaves** | Yes | Yes, inside the enclave | Primary |
| **Google Confidential Space** | Yes | Yes, inside the TEE | Primary or DR / standby |
| File-based vault | Yes | Import only | Development and test |

Both TEE backends provide hardware-attested isolation: the private key is generated inside the TEE, never leaves it in plaintext, and the signing workload is cryptographically attested by the host platform. This is the closest cloud equivalent to single-tenant HSM for BLS available today.

We track BLS support across cloud KMS providers and will add backends as they become viable.

---

## Deployment patterns we see in production

**Single-TEE, single-region.** Simplest path. Signatory in a Nitro Enclave or Confidential Space VM, baker colocated or across a private link. Suitable for operators who tolerate a cloud-provider outage as a bake-skip event.

**Multi-TEE active / standby.** Signatory deployed into AWS Nitro Enclaves as primary and Google Confidential Space as DR, each with its own sealed consensus key. Failover is a consensus key rotation, not a key migration. This is the pattern we operate with institutional customers today who can't treat a cloud-region outage as acceptable downtime. Running two independent TEE platforms across two cloud providers removes single-vendor dependency for consensus availability.

**Multi-key, multi-role.** A tz4 consensus key in a TEE, a separate tz4 companion key in the same or paired TEE for DAL, and tz1 / tz2 manager keys for application signing in whatever backend they already live in. Signatory runs all of these under one configuration and one policy surface.

---

## Migration path: tz1 / tz2 / tz3 to tz4

A typical migration for an existing Signatory operator:

1. **Provision a TEE backend.** Deploy Signatory into an [AWS Nitro Enclave](/docs/nitro) or [Google Confidential Space](/docs/confidential_space).
2. **Generate the tz4 consensus key inside the enclave** with `signatory-cli generate`. The private key is sealed to the TEE from the moment it exists.
3. **Enable Proof of Possession for the new key**, register it on-chain via an `Update_consensus_key` operation, then disable PoP.
4. **(Optional) Generate and register a companion tz4 key** for DAL attestations via `Update_companion_key`, using the same TEE-internal generation path. Required only if you want DAL reward eligibility; baseline tz4 consensus works without it.
5. **Cut over the baker** to sign under the new consensus key at the scheduled cycle.
6. **Retain the old tz1 / tz2 manager key** in your existing KMS or HSM backend for application signing. Signatory runs both key classes side by side under one configuration.

Full configuration examples live in [DAL & BLS Attestations](/docs/dal_bls_attestations) and [Proof of Possession](/docs/proof_of_possession).

---

## What you still get, with BLS keys

tz4 support in Signatory is not a stripped-down mode. Every control that applies to tz1 / tz2 / tz3 keys applies to tz4:

- **Per-key operation allowlists.** A consensus key can be restricted to `attestation` and `preattestation` and nothing else.
- **Watermark-based double-signing prevention**, persisted across restarts. [Firestore-backed watermarks](/docs/gcp_firestore) are available for multi-instance deployments needing shared state.
- **JWT-authenticated admin API**, so control-plane access is separate from signing access.
- **Prometheus metrics** for every sign call, broken down by key, operation type, and outcome. Grafana dashboards ship in the repo.
- **Remote policy hooks** for integration with external approval systems.
- **Structured audit logging** suitable for SIEM ingestion.

---

## Why BLS matters for Tezos consensus

BLS12-381 enables signature aggregation, which is what the `Attestations_aggregate` and `Preattestations_aggregate` operations (introduced in Seoul) lean on to keep the consensus committee efficient as it scales. But BLS also closes the door on most hardware wallets, because the BLS12-381 pairing math is too heavy for the secure elements those devices are built on. Every baker choosing to migrate to tz4 has to pick a new signing story.

For home bakers, the new generation of Raspberry Pi signers is a reasonable answer. For anyone operating at institutional scale, in the cloud, or under compliance constraints, the answer is a remote signer with attested key isolation, policy enforcement, and audit coverage. That's what Signatory is.

---

## Who builds Signatory

Signatory is built and continuously maintained by [ECAD Labs](https://ecadlabs.com/), and has been the remote signer of record for institutional Tezos deployments across exchanges, custodians, and validators-at-scale for years. The same team also maintains [Taquito](https://taquito.io/), the Tezos TypeScript SDK; [go-pkcs11](https://github.com/ecadlabs/go-pkcs11), the Go PKCS#11 bindings used across the ecosystem; and [goblst](https://github.com/ecadlabs/goblst), the Go BLS12-381 bindings. The BLS expertise behind this page isn't incidental; it's the curve we've been shipping production code against for years.

Active release cadence, shipping against each Tezos protocol as it lands. Commercial support, managed deployments, and custom backend integrations available on request.

---

## Get started

- **Docs:** [Signatory documentation](/docs/start)
- **Source:** [github.com/ecadlabs/signatory](https://github.com/ecadlabs/signatory)
- **Nitro Enclave quickstart:** [AWS Nitro backend](/docs/nitro)
- **Confidential Space quickstart:** [GCP Confidential Space backend](/docs/confidential_space)
- **DAL + BLS attestations:** [DAL & BLS Attestations](/docs/dal_bls_attestations)
- **Proof of Possession:** [Proof of Possession](/docs/proof_of_possession)
- **Commercial support and managed deployments:** [Contact ECAD Labs](https://ecadlabs.com/contact)
