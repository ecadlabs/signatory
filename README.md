![Signatory Logo](/docs/signatory-logo.png "Signatory Logo")

#### A Tezos Remote Signer

[![CII Best Practices](https://bestpractices.coreinfrastructure.org/projects/2778/badge)](https://bestpractices.coreinfrastructure.org/projects/2778)
[![GitHub Actions](https://github.com/ecadlabs/signatory/workflows/Test%20and%20publish/badge.svg)](https://github.com/ecadlabs/signatory/actions)
[![Maintainability](https://api.codeclimate.com/v1/badges/c1304869331b687e0aba/maintainability)](https://codeclimate.com/github/ecadlabs/signatory/maintainability)
[![Test Coverage](https://api.codeclimate.com/v1/badges/c1304869331b687e0aba/test_coverage)](https://codeclimate.com/github/ecadlabs/signatory/test_coverage)
[![Go Report Card](https://goreportcard.com/badge/github.com/ecadlabs/signatory)](https://goreportcard.com/report/github.com/ecadlabs/signatory)

## What is Signatory?

Signatory is a remote signing daemon that allows Tezos bakers and Tezos Application teams to protect their private keys.

The goal of the Signatory service is to make key management as secure as possible in a Cloud and on-premise HSM context.

## Why Use Signatory?

Security and convenience are typically at odds with each other. Signatory makes it easier for Tezos teams to manage their keys securely by offering several well-tested & supported signing options for cloud-based or hardware-based HSMs.

## Quick Start

[See docs](https://signatory.io/docs/start/)

---

## Features

### Remote Signing

Signatory receives requests to sign Tezos operations. These operations may be consensus operations when used in a Baking context, or they may be transactions or any other Tezos operation type.

Signatory will inspect the operations and assert that the operation request is in line with Signatory's policy. If the operation passes the policy rules, Signatory will then have a signature produced using the appropriate backend system. 

Signatory operators can choose from AWS, Azure or Google Cloud KMS systems, or self-hosted solutions such as the YubiHSM2, Hashicorp Vault or Ledger Hardware wallet.

### Observability

Signatory is also focused on observability, exposing metrics about its performance, volume and possible errors. Metrics allow operators to see historical trends, signing volumes, errors and latencies, enabling rich reporting and alerting capabilities.

### Private-Key Import

Private-key import is an important security consideration when choosing a Cloud KMS offering. Some KMS's allow you to generate the secret key internally so that no one can extract the private key from the HSM. Others allow for private-key import with different levels of security. The trade-offs in this context are essential to understand.

---

## How it Works

* A Tezos operation is sent to the Signatory API
* Signatory decodes and checks that the operation is permitted based on the defined policy
* Signatory sends the operation to the configured vault backend for signing
* Upon receiving the signature produced by backend, Signatory validates the signature
* Signatory returns the signature to Signatory client


## Why

Our goal in supporting multiple Cloud KMS/HSM services is to help prevent centralization on the _network_ or _infrastructure_ level. A goal of Tezos is to have a highly decentralized network of bakers. That goal is not fully realized if, of those bakers, a large majority operate on a single infrastructure provider.

In the first year of the Tezos network operation, there was anecdotal evidence that many bakers ran on AWS. AWS is a superb provider, but having a concentration of nodes on one cloud vendor centralizes the underlying infrastructure of the network, which is not desirable. By supporting multiple Cloud KMS/HSM systems, we hope to prevent the network from centralization on a particular Cloud offering.

## Supported Signing Backends

### Backend KMS/HSM Support Status

|                                | Status |
| ------------------------------ | ------ |
| YubiHSM2                       | ✅     |
| Azure KMS                      | ✅     |
| Google Cloud KMS               | ✅     |
| AWS KMS                        | ✅     |
| Ledger Nano S/S+ (Baking only) | ✅     |
| Hashicorp Vault                | ✅     |
| PKCS#11                        | ✅     |

### Tezos Address Types

In Tezos, you can infer the signing algorithm from the first three characters of an address. For example, an address beginning with `tz3` uses the P-256 algorithm. HSMs and Cloud-based HSMs have support for a subset of the three algorithms supported by Tezos.

* `tz1` - [Ed25519](https://ed25519.cr.yp.to/)
* `tz2` - [Secp256k1](https://en.bitcoin.it/wiki/Secp256k1) __aka: P256K__
* `tz3` - P-256
* `tz4` - BLS12-381

## Signing Algorithm Support From Various Backends

|                  | tz1 | tz2 | tz3 |
| ---------------- | --- | --- | --- |
| Hashicorp Vault  | ✅   | ❌   | ❌   |
| Google Cloud KMS | ❌   | ❌   | ✅   |
| AWS KMS          | ❌   | ✅   | ✅   |
| Azure KMS        | ❌   | ✅   | ✅   |
| YubiHSM2         | ✅   | ✅   | ✅   |
| PKCS#11          | ❌   | ✅   | ✅   |

---

## Reporting Issues

### Security Issues

To report a security issue, please contact security@ecadlabs.com

### Other Issues & Feature Requests

Please use the [GitHub issue tracker](https://github.com/ecadlabs/signatory/issues) to report bugs or request features.

## Contributions

To contribute, please check the issue tracker to see if an issue exists for your planned contribution. If there's no issue, please create one first, and then submit a pull request with your contribution.

For a contribution to be merged, it is required to have complete documentation and come with unit tests and integration tests where appropriate. Submitting a "work in progress" pull request is welcome!

---

## Alternative Remote Signers

At least three other remote signers are available to use with Tezos. Tezos also provides native support for baking with a Ledger Nano. We encourage bakers to, at a minimum, review these projects. We are eager to collaborate and be peers with these great projects.

* [Tezzigator's Azure remote signer](https://github.com/tezzigator/azure-tezos-signer)
* [Tacoinfra's remote signer](https://github.com/tacoinfra/remote-signer)
* [Polychain Labs' remote signer](https://gitlab.com/polychainlabs/tezos-hsm-signer)

## Disclaimer

THIS SOFTWARE IS PROVIDED "AS IS" AND ANY EXPRESSED OR IMPLIED WARRANTIES,
INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE REGENTS
OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
OF SUCH DAMAGE.

[0]: https://azure.microsoft.com/en-ca/services/key-vault/


