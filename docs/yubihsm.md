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

```
apt-get install libusb-1.0-0
```

To install the connector, find and install the 

```
dpkg -i yubihsm-connector_2.1.0-1_amd64.deb
```

To manage the YubiHSM2 device, you will need the `yubihsm-shell` utility. This utility requires the installation of the `libedit2` package.

```
apt-get install libedit2
```

To install yubihsm-shell, you must install the yubihsm-shell package and the supporting YubiHSM2 libraries. The `yubihsm-shell` is not required for the operation of Signatory and is only for the management of the YubiHSM2 device.

```
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

```
yubihsm>
```

To connect to the device, type `connect`. It will automatically connect to localhost.

To open a new session with the device type. The default password on the YubiHSM2 is "password".

```
yubihsm> session open 1 password
```

To list all objects on the device, run the command.

```
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
  # Name is used to identify backend during import process
  yubi:
    driver: yubihsm
    config:
      address: localhost:12345 # Address for the yubihsm-connector
      password: password
      auth_key_id: 1
```

To import a secret key, we take the secret key from the above JSON examples. Do not include the "encrypted:" or "unencrypted:" prefix.

```
signatory-cli import --config ./signatory.yaml --vault yubi edsk2rKA8YEExg9Zo2qNPiQnnYheF1DhqjLVmfKdxiFfu5GyGRZRnb
```

If the import is successful, the `signatory-cli` will report the PKH of your newly imported secret:

```
INFO[0000] Initializing vault                            vault=yubihsm vault_name=yubi
INFO[0000] Requesting import operation                   pkh=tz1SBhzLDp9Jvg98ztMZMstaKbAENmzRd4Y7 vault=YubiHSM vault_name="localhost:12345/1"
INFO[0000] Successfully imported                         key_id=0cf8 pkh=tz1SBhzLDp9Jvg98ztMZMstaKbAENmzRd4Y7 vault=YubiHSM vault_name="localhost:12345/1"
```

If you import an encrypted key, the `signatory-cli` command will prompt you for a password.

You can use the `yubihsm-shell` utility command `list objects 0 0` to verify that you can also see your newly imported secret within the YubiHSM2 device.

### Listing Tezos Addresses in the YubiHSM2

You can use the command `signatory-cli list` to list all keys in the YubiHSM2. `signatory-cli` also prints the configuration status for each address.

```
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
  # Name is used to identify backend during import process
  yubi:
    driver: yubihsm
    config:
      address: localhost:12345 # Address for the yubihsm-connector
      password: password
      auth_key_id: 1
tezos:
  tz1SBhzLDp9Jvg98ztMZMstaKbAENmzRd4Y7:
    log_payloads: true
    allowed_operations:
      - generic
    allowed_kinds:
      - origination
```

Rerun the `signatory-cli list` command to verify that your new address is getting picked up, and is configured as you expect.

```
signatory-cli -c ./signatory.yaml list
Public Key Hash:    tz1SBhzLDp9Jvg98ztMZMstaKbAENmzRd4Y7
Vault:              YubiHSM
ID:                 0cf8
Status:             Active
Allowed Operations: [generic]
Allowed Kinds:      [ballot]
```

[yubihsm]: https://www.yubico.com/products/hardware-security-module/ 
[yubisdk]: https://developers.yubico.com/YubiHSM2/Releases/



---

## Alex's Changes for website to see how they look:

Note on convention: Anything surrounded by curly brackets is a piece of info that will be specific to you. For example {tezos_public_key_hash} will be something on your system resembling `tz1P572ijpP...`

### Introduction to YubiHSM2:

They will likely describe their own products far better than we ever could. Some resources on the HSM are available here:

- [HSM website](https://www.yubico.com/products/hardware-security-module/) (make sure to check out the product brief on this page)
- [Developers Overview](https://developers.yubico.com/YubiHSM2/Product_Overview/)
- [HSM Series Support Page](https://www.yubico.com/ca/setup/yubikey-5-series/)

#### Trade-offs of using YubiHSM:
To be completed later

### Vault Setup Hints
This is the guide that was used to set up the HSM initially and gather the required tool to interface with different hosts: 
(This should get the HSM connected to your host and able to receive commands)
- [Quick Start](https://developers.yubico.com/YubiHSM2/Usage_Guides/YubiHSM_quick_start_tutorial.html)
    - You will need to complete up to and including the section titled "Adding a New Authentication Key". This will make sure your environment is set up to allow asymmetric key generation
    - One part of this is possibly defining a udev rule for allowing your user to access the yubiHSM since running things as root isn't generally advised. This [link](https://developers.yubico.com/YubiHSM2/Component_Reference/yubihsm-connector/) is helpful for setting up udev rules so your user can run the connector

### Key Management
- You will need to complete the section titled "Generate a Key for Signing". This will create the keys that the HSM will use for signing. A single key is generally enough to get what you need done and if you need more, they can be added in the future.

### Signatory Setup for most cases (no different setup needed for Yubi at this time)
I don't believe there is anything additional needed for signatory when using a YubiHSM. The standard should work:
- Clone [repo](https://github.com/ecadlabs/signatory)
- Make sure Go is installed (version must be greater than 1.12(I think))
- Navigate to the cloned signatory repo
- `make signatory`
- `make signatory-cli`

#### What you need for YubiHSM in a signatory configuration YAML file
The following is needed in a config file for signatory to know what it is looking for on a yubiHSM
```
# The vaults section is what defines the connection to the yubiHSM
vaults:
# Name is used to identify backend
  yubi:
    driver: yubihsm
    config:
      address: localhost:12345 # Address for the yubihsm-connector
      password: {password_you_set_when_creating_authentication_key}
      auth_key_id: 1 # This is the ID of the authentication key you created for the YubiHSM

# This section is for public key hashes to define what is activated IRL
tezos:
  # Default policy allows "block" and "endorsement" operations
  {tezos_public_key_hash}:
  #tz1RKhyJmze24D3EerrGpCZG6P572ijpPUc3(for example):
    log_payloads: true
    allowed_operations:
    # List of [generic, block, endorsement]
    - generic
    - block
    - endorsement
```

### Signatory-cli features for YubiHSM
Once you have signatory binaries and the YubiHSM set up it is time to test the connection between the hardware and signatory. After completing the setup for the HSM and signatory we can test it by using the signatory-cli command `list`. Here is an example:
```
alexander@debian:~/signatory$ ./signatory-cli list --help
List public keys

Usage:
  signatory-cli list [flags]

Flags:
  -h, --help   help for list

Global Flags:
  -c, --config string   Config file path (default "/etc/signatory.yaml")
      --log string      Log level: [error, warn, info, debug, trace] (default "info")
      
alexander@debian:~/signatory$ ./signatory-cli list -c signatory.yaml 
INFO[0000] Initializing vault                            vault=yubihsm vault_name=yubi
Public Key Hash:    tz1RKhyJmze24D3EerrGpCZG6P572ijpPUc3
Vault:              YubiHSM
ID:                 bf5d
Active:             true
Allowed Operations: [block endorsement generic]
Allowed Kinds:      []
```

### Tezos Client Setup
Adding the information generated in any vault to the tezos-client is done in a single command, it is as follows:

`tezos-client import secret key {name_you_choose} http://localhost:6732/{your_public_key_hash}`

Using the same pkh as above an example command would look like:

`tezos-client import secret key yubi_guide http://localhost:6732/tz1RKhyJmze24D3EerrGpCZG6P572ijpPUc3`

This should produce the output: `Tezos address added: tz1RKhyJmze24D3EerrGpCZG6P572ijpPUc3`

Making the added PKH a delegate to begin baking/endorsing is achieved through this command (node/baker/endorser should be running already):

`tezos-client register key {name_you_chose} as delegate`

### Final Signatory Verification Test
We can finally see that all the pieces are working together by curling the signatory service and asking for the public key associated with our active public key hash:
`curl http://localhost:6732/keys/tz1RKhyJmze24D3EerrGpCZG6P572ijpPUc3`

The output can be verified by checking the public_keys file in the .tezos-client directory