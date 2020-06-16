---
id: start
title: Getting Started
sidebar_label: Getting Started
---


## What is Signatory

Signatory is a remote signing daemon that allows Tezos bakers to sign endorsement and baking operations with a variety of different key-management systems.

Signatory currently supports [YubiHSM][yubi], [Azure Key Vault][azure], and for development/prototyping purposes, Signatory can sign with a local private key.

The goal of the Signatory service is to make key-management as secure as possible in a Cloud and on-premise HSM context.

Security and convenience are often diametrically opposed, but we hope to at least make it easier for the community to manage their keys in an adequately secure manner.

By supporting multiple Cloud KMS/HSM systems, we hope to help the network from centralization on a particular Cloud offering. In the first year of the Tezos network operation, there's anecdotal evidence that a lot of bakers run on AWS. AWS is a superb provider, but having a concentration of nodes on one cloud vendor centralizes the underlying infrastructure of the network which is not desirable.

Observability is a first-class concern of Signatory. Signatory exposes metrica about its operation via Promteheus metrics. Enabling teams to set up robust monitoring of their critical infrastrucure. Allowing operators to see historic trends, signing volumes, errors and latencies. This allows for rich reporting and alerting capabilities.


Feature requests, security issues or bug reports can be reported via the Github project page: github.com/ecadlabs/signatory or via email to security@ecadlabs.com

Security issues can be encrypted using the keys available at keybase/jevonearth

[yubi]: https://www.yubico.com/products/hardware-security-module/
[azure]: https://docs.microsoft.com/en-us/azure/key-vault/