---
id: yubihsm
title: YubiHSM
---

# What is YubiHSM?

_Taken from the [Yubico website][yubihsm]_

_The YubiHSM 2 is a Hardware Security Module that is within reach of all organizations. It provides advanced cryptography, including hashing, asymmetric and symmetric key cryptography, to protect the cryptographic keys that secure critical applications, identities, and sensitive data in an enterprise for certificate authorities, databases, code signing and more._

YubiHSM is a hardware-based HSM device. This device is suitable for use where you have access to your physical servers.

## Setup with Signatory

### Prerequisites

* A Linux system operably configured with:
  * Docker (Possible to operate outside of )
  * The [yubihsm2 sdk][yubisdk] installed. This documentation assumes you are using docker on Debian.

_Setup documentation coming soon_

[yubihsm]: https://www.yubico.com/products/hardware-security-module/ 
[yubisdk]: https://developers.yubico.com/YubiHSM2/Releases/