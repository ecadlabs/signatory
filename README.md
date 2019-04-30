# signatory

Signatory - A Tezos Remote Signer

__WARNING: This project is in active development, while we welcome users and
feedback, please be warned that this project is a work in progress and users
should proceed with judicious caution.__

Signatory is a remote signer, that receives signing requests from either a
baker or an endorser, signs the data and returns the data with a signature.

The service supports, or will support a variety of back-end Key Management
Systems (KMS) for secure handling of private keys. Most cloud based KMS systems
offer a HSM backed mode, which is strongly recommended.

## Back-end KMS/HSM support status

|                  | Status      |
|------------------|-------------|
| Google Cloud KMS | Planned     |
| Azure KMS        | In Progress |
| AWS KMS          | Planned     |
| YubiHSM2         | Evaluating  |

## Signing Algorithm support from various back-ends

In tezos, the signing algorithm can be inferred from the address type. An
address beginning with `tz3` uses the P-256 algorithm. Various HSMs and Cloud
based HSM's support different algorithms. 

|                  | tz1 address (Ed25519) | tz2 address (Secp256k1) | tz3 address (p-256) |
|------------------|-----------------------|-------------------------|---------------------|
| Google Cloud KMS | no                    | no                      | yes                 |
| AWS KMS          | no                    | no                      | yes                 |
| Azure KMS        | no                    | no                      | yes                 |
| YubiHSM2         | yes                   | yes                     | yes                 |


## Key import capabilities

Key import is an important security consideration when choosing a Cloud HSM
offering. Some HSM's allows you to generate the secret key internally, and the
secret key can never be exported. Others allow for key import with different
levels of security. The trade-offs in this setting are important.


# Contributions

## Reporting issues/feature requests

Please use the [GitHub issue
tracker](https://github.com/ecadlabs/go-tezos/issues) to report bugs or request
features.

## Contribution

To contribute, please check the issue tracker to see if an existing issue
exists for your planned contribution. If there's no Issue, please create one
first, and then submit a pull request with your contribution. 

For a contribution to be merged, it must be well documented, come with unit
tests, and integration tests where appropriate. Submitting a "Work in progress"
pull request is welcome!

## Reporting Security Issues

If a security vulnerabiltiy in this project is discovered, please report the
issue to security@ecadlabs.com or to `jevonearth` on keybase.io

Reports may be encrypted using keys published on keybase.io

