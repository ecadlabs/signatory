---
id: yubihsm
title: YubiHSM
---

# What is YubiHSM2?

_Taken from the [Yubico website][yubihsm]_

_The YubiHSM 2 is a Hardware Security Module that is within reach of all organizations. It provides advanced cryptography, including hashing, asymmetric and symmetric key cryptography, to protect the cryptographic keys that secure critical applications, identities, and sensitive data in an enterprise for certificate authorities, databases, code signing and more._

YubiHSM2 is a hardware-based HSM device. This device is suitable for use where you have access to your physical servers.

## Setup with Signatory

### Prerequisites

In this guide, we use Docker for convenience, but you are not required to use Docker.

This documentation assumes that you will be running Signatory and the YubiHSM2 device on the same physical server.

* A Linux system operably configured with:
  * Docker
  * The [yubihsm2 sdk][yubisdk] version 2012.12 or later installed. This documentation assumes you are using Docker on Debian.
* A YubiHSM device connected to your server. (See the output of `lsusb` to verify)

### Installing and using the YubiHSM Connector and Shell

Signatory uses the `yubihsm-connector` daemon to interact with the YubiHSM USB device.

The connector requires you to have the libusb package installed on your system.

```bash
apt-get install libusb-1.0-0
```

To install the connector, find and install the 

```bash
dpkg -i yubihsm-connector_2.1.0-1_amd64.deb
```

To manage the YubiHSM2 device, you will need the `yubihsm-shell` utility. This utility requires the installation of the `libedit2` package.

```bash
apt-get install libedit2
```

To install yubihsm-shell, you must install the yubihsm-shell package and the supporting YubiHSM2 libraries. The `yubihsm-shell` is not required for the operation of Signatory and is only for the management of the YubiHSM2 device.

```bash
dpkg -i yubihsm-shell_2.0.2-1_amd64.deb \
    libyubihsm1_2.0.2-1_amd64.deb \
    libyubihsm-http1_2.0.2-1_amd64.deb \
    libyubihsm-usb1_2.0.2-1_amd64.deb
```

### Connecting to the YubiHSM2 device with yubihsm-shell

Start the `yubihsm-connector`

```bash
yubihsm-connector
```

Run the command `yubihsm-shell`. You will get a prompt that looks like:

```bash
yubihsm>
```

To connect to the device, type `connect`. It will automatically connect to localhost.

To open a new session with the device type. The default password on the YubiHSM2 is "password".

```bash
yubihsm> session open 1 password
```

To list all objects on the device, run the command.

```bash
yubihsm> list objects 0 0
```

### Importing a Secret key into the YubiHSM2 for Tezos

To import a secret key, we will use the `signatory-cli` command.

Here are six examples of private keys for test/evaluation purposes. Three encrypted (password is "test") and three unencrypted.

```json
[ { "name": "ed25519_encrypted",
    "value":
      "encrypted:edesk1GXwWmGjXiLHBKxGBxwmNvG21vKBh6FBxc4CyJ8adQQE2avP5vBB57ZUZ93Anm7i4k8RmsHaPzVAvpnHkFF" },
  { "name": "secp256k1_encrypted",
    "value":
      "encrypted:spesk24UQkAiJk8X6AufNtRv1WWPp2BAssEgmijCTQPMgUXweSKPmLdbyAjPmCG1pR2dC9P5UZZVeZcb7zVodUHZ" },
  { "name": "p256_encrypted",
    "value":
      "encrypted:p2esk28hoUE2J88QNFj2aDX2pjzL7wcVh2g8tkEwtWWguby9M3FHUgSbzvF2Sd7wQ4Kd8crFwvto6gF3otcBuo4T" },
  { "name": "p256_unencrypted",
    "value":
      "unencrypted:p2sk3HdQc93EjixRAWs9WZ6b3spNgPD7VriXU8FH8EiHN8sxCh7gmv" },
  { "name": "secp256k1_unencrypted",
    "value":
      "unencrypted:spsk2Fiz7sGP5fNMJrokp6ynTa4bcFbsRhw58FHXbNf5ProDNFJ5Xq" },
  { "name": "ed25516_unencrypted",
    "value":
      "unencrypted:edsk2rKA8YEExg9Zo2qNPiQnnYheF1DhqjLVmfKdxiFfu5GyGRZRnb" } ]
```

The `signatory-cli` command needs a configuration file. The following will suffice;

```yaml
server:
  address: localhost:6732
  utility_address: localhost:9583

vaults:
  yubi:
    driver: yubihsm
    config:
      address: localhost:12345 # Address for the yubihsm-connector
      password: password
      auth_key_id: 1
```

To import a secret key, we take the secret key from the above JSON examples. Do not include the "encrypted:" or "unencrypted:" prefix.

```bash
signatory-cli import --config ./signatory.yaml --vault yubi
```

If the import is successful, the `signatory-cli` will report the PKH of your newly imported secret:

```bash
INFO[0000] Initializing vault                            vault=yubihsm vault_name=yubi
Enter secret key: 
Enter Password:
INFO[0000] Requesting import operation                   pkh=tz1SBhzLDp9Jvg98ztMZMstaKbAENmzRd4Y7 vault=YubiHSM vault_name="localhost:12345/1"
INFO[0000] Successfully imported                         key_id=0cf8 pkh=tz1SBhzLDp9Jvg98ztMZMstaKbAENmzRd4Y7 vault=YubiHSM vault_name="localhost:12345/1"
```

If you import an encrypted key, the `signatory-cli` command will prompt you for a password.

You can use the `yubihsm-shell` utility command `list objects 0 0` to verify that you can also see your newly imported secret within the YubiHSM2 device.

### Listing Tezos Addresses in the YubiHSM2

You can use the command `signatory-cli list` to list all keys in the YubiHSM2. `signatory-cli` also prints the configuration status for each address.

```bash
signatory-cli -c ./signatory.yaml list
Public Key Hash:    tz1SBhzLDp9Jvg98ztMZMstaKbAENmzRd4Y7
Vault:              YubiHSM
ID:                 0cf8
Status:             Disabled
```

### Configuring your newly imported address

Add the PKH for your new secret into the `tezos:` block of your `signatory.yaml` file as follows:

```yaml
server:
  address: localhost:6732
  utility_address: localhost:9583

vaults:
  yubi:
    driver: yubihsm
    config:
      address: localhost:12345
      password: password
      auth_key_id: 1
tezos:
  tz1SBhzLDp9Jvg98ztMZMstaKbAENmzRd4Y7:
    log_payloads: true
    allow:
      generic:
        - origination
```

Rerun the `signatory-cli list` command to verify that your new address is getting picked up, and is configured as you expect.

```bash
signatory-cli -c ./signatory.yaml list
Public Key Hash:    tz1SBhzLDp9Jvg98ztMZMstaKbAENmzRd4Y7
Vault:              YubiHSM
ID:                 0cf8
Status:             Active
Allowed Operations: [generic]
Allowed Kinds:      [origination]
```

[yubihsm]: https://www.yubico.com/products/hardware-security-module/ 
[yubisdk]: https://developers.yubico.com/YubiHSM2/Releases/
