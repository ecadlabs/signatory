# Signatory - A Tezos Remote Signer

[![CircleCI](https://circleci.com/gh/ecadlabs/signatory.svg?style=svg)](https://circleci.com/gh/ecadlabs/signatory)
[![Maintainability](https://api.codeclimate.com/v1/badges/c1304869331b687e0aba/maintainability)](https://codeclimate.com/github/ecadlabs/signatory/maintainability)
[![Test Coverage](https://api.codeclimate.com/v1/badges/c1304869331b687e0aba/test_coverage)](https://codeclimate.com/github/ecadlabs/signatory/test_coverage)

__WARNING: This project is in active development, while we welcome users and
feedback, please be warned that this project is a work in progress and users
should proceed with judicious caution.__

Signatory is a remote signing daemon that allows Tezos bakers to securely sign
endorsement and baking operations with a variety of different key management
systems.

The goal of the Signatory service is to make key management as secure as
possible in a Cloud and on premise HSM context.

It receives signing requests from either a baker or an endorser, signs the data
using one of its backends, and then returns a signature.

Signatory currently supports [Azure Key Vault][0], and other backend signing
services are either in planning phase, or being added.

Security and convenience are typically diametrically opposed, but we hope to at
least make it easier for the community to manage their keys in an adequately
secure manner.

Signatory is also focused on observability. Meaning that it exposes metrics
about its operations. Allowing operators to see historic trends, signing
volumes, errors and latencies. This allows for rich reporting and alerting
capabilities.

By supporting multiple Cloud KMS/HSM systems, we hope to help the network from
centralization on a particular Cloud offering. In the first year of the Tezos
network operation, there's anecdotal evidence that a lot of bakers run on AWS.
AWS is a superb provider, but having a concentration of nodes on one cloud
vendor centralizes the underlying infrastructure of the network which is not
desirable.

The service supports, or will support a variety of backend Key Management
Systems (KMS) for secure handling of private keys. Most cloud based KMS systems
offer a HSM backed mode, which is strongly recommended.

## How it works

* Tezos will send a signing request to `Signatory`
* Signatory checks that the operation is either `block` or `endorsement`
* Signatory will send the operation to the configured backend for singing
* Upon receiving the signing operation from the backend, Signatory will validate the signature with a Tezos node (optional)
* Signatory returns the operation signature to the Tezos node

## Backend KMS/HSM support status

|                  | Status      |
| ---------------- | ----------- |
| Azure KMS        | In Progress |
| Google Cloud KMS | Planned     |
| AWS KMS          | Planned     |
| YubiHSM2         | Evaluating  |

### Tezos address types

In Tezos, the signing algorithm can be inferred from the the first three
characters of an address. For example, an address beginning with `tz3` uses the
P-256 algorithm. HSM's and Cloud based HSM's have support for a subset of the
three algorithims supported by Tezos.

* `tz1` - [Ed25519](https://ed25519.cr.yp.to/)
* `tz2` - [Secp256k1](https://en.bitcoin.it/wiki/Secp256k1) __aka: P256K__
* `tz3` - P-256

## Signing Algorithm support from various backends

|                  | tz1 | tz2 | tz3 |
| ---------------- | --- | --- | --- |
| Google Cloud KMS | ☒   | ☒   | ☑   |
| AWS KMS          | ☒   | ☒   | ☑   |
| Azure KMS        | ☒   | ☑   | ☑   |
| YubiHSM2         | ☑   | ☑   | ☑   |

## Key import capabilities

Key import is an important security consideration when choosing a Cloud HSM
offering. Some HSM's allow you to generate the secret key internally, and the
secret key can never be exported. Others allow for key import with different
levels of security. The trade-offs in this setting are important.

# Contributions

## Reporting issues/feature requests

Please use the [GitHub issue
tracker](https://github.com/ecadlabs/signatory/issues) to report bugs or request
features.

## Contribution

To contribute, please check the issue tracker to see if an existing issue
exists for your planned contribution. If there's no Issue, please create one
first, and then submit a pull request with your contribution. 

For a contribution to be merged, it must be well documented, come with unit
tests, and integration tests where appropriate. Submitting a "Work in progress"
pull request is welcome!

## Reporting Security Issues

To report a security issue, please contact security@ecadlabs.com or
via [keybase/jevonearth][1] on keybase.io

Reports may be encrypted using keys published on keybase.io using 
[keybase/jevonearth][1]

## Alternative remote signers

At least three other remote signers are available, and Ledger support for
baking. We encourage bakers to, at a minimum review these projects. We
are proud to collaborate and be peers with these great projects.

* https://github.com/tezzigator/azure-tezos-signer
* https://github.com/tacoinfra/remote-signer
* https://gitlab.com/polychain/tezos-hsm-signer

[0]: https://azure.microsoft.com/en-ca/services/key-vault/
[1]: https://keybase.io/jevonearth
