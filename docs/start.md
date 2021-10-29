---
id: start
title: Getting Started
sidebar_label: Getting Started
---


## What is Signatory

Signatory is a remote signing daemon that allows Tezos bakers to sign endorsement and baking operations with various key-management systems.

Signatory currently supports [YubiHSM][yubi], [Azure Key Vault][azure], and for development/prototyping purposes, Signatory can sign with a local private key.

The goal of the Signatory service is to make key management as secure as possible in a Cloud and on-premise HSM context.

Security and convenience are often opposed, but we hope to make it easier for the community to manage their keys in an adequately secure manner.

By supporting multiple Cloud KMS/HSM systems, we hope to help the network from centralization on a particular Cloud offering. In the first year of the Tezos network operation, there's anecdotal evidence that many bakers run on AWS. AWS is a superb provider, but concentrating nodes on one cloud vendor centralizes the network’s underlying infrastructure, which is not desirable.

Observability is a first-class concern. Signatory allows for rich reporting and alerting capabilities. It exposes metrics about its operation via Prometheus metrics, enabling teams to set up robust monitoring of their critical infrastructure and allowing operators to see historical trends, signing volumes, errors and latencies. Users can report feature requests, security issues, or bug reports can via the Github project page: 
github.com/ecadlabs/signatory or via email to security@ecadlabs.com

Security issues can be encrypted using the keys available at keybase/jevonearth

[yubi]: https://www.yubico.com/products/hardware-security-module/
[azure]: https://docs.microsoft.com/en-us/azure/key-vault/