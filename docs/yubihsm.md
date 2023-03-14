---
id: yubihsm
title: YubiHSM
---
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

#### Key generation on YubiHSM
- You will need to complete the section titled "Generate a Key for Signing". This will create the keys that the HSM will use for signing. A single key is generally enough to get what you need done and if you need more, they can be added in the future.

#### Importing a Secret key into the YubiHSM2 for Tezos


#### What you need for YubiHSM in a signatory configuration YAML file
The following is needed in a config file for signatory to know what it is looking for on a yubiHSM

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
yubihsm> list objects 1 0
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
  # Default policy allows "block" and "endorsement" operations
  {public_key_hash}:
    log_payloads: true

    allowed_operations:
      # List of [generic, block, endorsement]
      - generic
      - block
      - endorsement
    allowed_kinds:
      # List of [endorsement, ballot, reveal, transaction, origination, delegation, seed_nonce_revelation, activate_account]
      - transaction
      - endorsement
      - reveal
      - delegation
    authorized_keys:
      # Allow sign operation only for clients specified below. Same syntax as `server/authorized_key`
      - *authorized_key
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

### Final Signatory Verification Test
We can finally see that all the pieces are working together by curling the signatory service and asking for the public key associated with our active public key hash:
`curl http://localhost:6732/keys/{your_public_key_hash}`

The output can be verified by checking the public_keys file in the .tezos-client directory