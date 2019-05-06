# Signatory - A Tezos Remote Signer

[![CircleCI](https://circleci.com/gh/ecadlabs/signatory.svg?style=svg)](https://circleci.com/gh/ecadlabs/signatory)
[![Maintainability](https://api.codeclimate.com/v1/badges/c1304869331b687e0aba/maintainability)](https://codeclimate.com/github/ecadlabs/signatory/maintainability)
[![Test Coverage](https://api.codeclimate.com/v1/badges/c1304869331b687e0aba/test_coverage)](https://codeclimate.com/github/ecadlabs/signatory/test_coverage)

__WARNING: This project is in active development, while we welcome users and
feedback, please be warned that this project is a work in progress and users
should proceed with judicious caution.__

Signatory is a remote signing daemon that allows Tezos bakers to sign
endorsement and baking operations with a variety of different key management
systems.

It receives signing requests from either a baker or an endorser, signs the data
using one of its backends, and then returns a signature.

Signatory currently supports [Azure Key Vault][0], and other backend signing
services are either in planning phase, or being added.

The goal of the Signatory service is to make key management as secure as
possible in a Cloud and on premise HSM context.

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

## Backend KMS/HSM support status

|                  | Status      |
| ---------------- | ----------- |
| Azure KMS        | In Progress |
| Google Cloud KMS | Planned     |
| AWS KMS          | Planned     |
| YubiHSM2         | Evaluating  |

## Signing Algorithm support from various backends

In Tezos, the signing algorithm can be inferred from the address type. For
example, an address beginning with `tz3` uses the P-256 algorithm. Various HSM's
and Cloud based HSM's support different algorithms. 

|                  | tz1 address (Ed25519) | tz2 address (Secp256k1) | tz3 address (p-256) |
| ---------------- | --------------------- | ----------------------- | ------------------- |
| Google Cloud KMS | no                    | no                      | yes                 |
| AWS KMS          | no                    | no                      | yes                 |
| Azure KMS        | no                    | yes*                    | yes                 |
| YubiHSM2         | yes                   | yes                     | yes                 |

`* Azure tz2/Secp256k1 support has a bug where some signatures fail`


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
baking. We encourage bakers to at the minimum review these projects. We
are proud to collaborate and be peers with these great projects.

* https://github.com/tacoinfra/remote-signer
* https://gitlab.com/polychain/tezos-hsm-signer
* https://github.com/tezzigator/azure-tezos-signer


[0]: https://azure.microsoft.com/en-ca/services/key-vault/
[1]: https://keybase.io/jevonearth
