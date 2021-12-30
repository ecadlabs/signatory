---
id: start
title: Getting Started
sidebar_label: Getting Started
---


## What is Signatory

Signatory is a remote signing daemon. Signatory can be used by Tezos Bakers to add additional security to their systems. Signatory can also be used by applications that require signatures but do not want to have the responsibility of storing secret keys.

Signatory currently supports [YubiHSM][yubi], [Azure Key Vault][azure], and for development/prototyping purposes, Signatory can sign with a local private key.

The goal of the Signatory service is to make key management as secure as possible in a Cloud and on-premise HSM context.

Security and convenience are often opposed, but we hope to make it easier for the community to manage their keys in an adequately secure manner.

By supporting multiple Cloud KMS/HSM systems, we hope to help the network from centralization on a particular Cloud offering. In the first year of the Tezos network operation, there was anecdotal evidence that many bakers run on AWS. AWS is a superb provider, but concentrating nodes on one cloud vendor centralizes the network’s underlying infrastructure, which is not desirable.

Observability is a first-class concern. Signatory allows for rich reporting and alerting capabilities. It exposes metrics about its operation via Prometheus metrics, enabling teams to set up robust monitoring of their critical infrastructure and allowing operators to see historical trends, signing volumes, errors and latencies. Users can report feature requests, security issues, or bug reports can via the Github project page: 
github.com/ecadlabs/signatory or via email to security@ecadlabs.com

Security issues can be encrypted using the keys available at keybase/jevonearth

[yubi]: https://www.yubico.com/products/hardware-security-module/
[azure]: https://docs.microsoft.com/en-us/azure/key-vault/

## Following this guide

:::note Conventions
Text surrounded by curly brackets is a piece of info that will be specific to you. For example, the reader should replace `{tezos_public_key_hash}` with your Tezos Address (Public Key Hash) which starts with either `tz1`, `tz2`, or `tz3`, and looks like `tz1Ke2h7sDdakHJQh8WX4Z372du1KChsksyU`.
:::

## Signatory Configuration

Signatory reads a YAML configuration file. <!-- TODO: Explain config file structure here-->

