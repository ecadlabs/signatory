---
id: ledger
title: Ledger
---

# Ledger vault

Connect the ledger device to the system in which signatory is running.
Install tezos-wallet and tezos-baker apps from [ledger live](https://www.ledger.com/ledger-live/download).

Note: Developer mode might be needed to install baker app.
[Ledger Developer mode](https://developers.ledger.com/docs/live-app/developer-mode/#:~:text=To%20activate%20the%20Developer%20mode,Live%20version%202.32%20and%20above.)

## Configuration

| Name        | Type         | Required | Description                                                   |
|-------------|--------------|----------|---------------------------------------------------------------|
| id          | string       |     ✅    | Ledger Device ID. Use first available device if not specified |
| keys        | string array |     ✅    | Managed key IDs                                               |
| close_after | duration     |    OPTIONAL      | Close device after a certain period of inactivity             |

### Keys & ID format and meaning

Syntax: `derivation/bip32`

Where `bip32` is [BIP 0032](https://en.bitcoin.it/wiki/BIP_0032) path and
`derivation` is one of derivation schemes: `ed25519`, `secp256k1`, `p-256`,
`secp256r1` (alias for `p-256`), `bip25519`, `bip32-ed25519` (alias for
`bip25519`). `bip25519` is a [BIP 0032](https://en.bitcoin.it/wiki/BIP_0032)
compliant scheme, others use some sort of a custom hash chain.

Ledger specific root `m/44'/1729'` may be omitted.

Examples (equivalent): `bip32-ed25519/m/44'/1729'/0'/0'`,
`bip32-ed25519/44'/1729'/0'/0'`, `bip25519/0'/0'`

### Example

```yaml
vaults:
  ledger:
    driver: ledger
    config:
      id: 3944f7a0
      keys:
        - "bip32-ed25519/0'/0'"
        - "secp256k1/0'/1'"
      close_after: 3600s
```

### **close_after field in config**

Configure this value as per your requirement. As you don't know the time between the blocks assigned to your baker, it is better to configure it for at least a few hours to prevent the ledger from closing, often due to inactivity.

Example:

```sh
close_after: 3600s
```

### Transports

By default Ledger vault uses `usb` transport. Another available transport is `tcp` used primarily for interaction with [Speculos](https://github.com/LedgerHQ/speculos)
emulator. It can be enabled using `transport` option:

```yaml
vaults:
  ledger:
    driver: ledger
    config:
      id: 3944f7a0
      transport: tcp://127.0.0.1:9999
      keys:
        - "bip32-ed25519/0'/0'"
        - "secp256k1/0'/1'"
      close_after: 3600s
```

In addition `signatory-cli ledger` command also accepts `-t` / `--transport` key with the same URL-like syntax:

```sh
signatory-cli ledger --transport 'tcp://127.0.0.1:9999' list
```

## Getting data from ledger for signatory configuration using CLI

Keep tezos-wallet app open for the below commands and for signing any wallet transactions.
During every wallet transaction `Accept/Reject` input should be provided in the ledger when prompted.

```sh
    % ./signatory-cli list -c ./sig-ledger.yaml 
    INFO[0000] Initializing vault                            vault=ledger vault_name=ledger
    Public Key Hash:    tz1TrrJS7XU2WGJJEZcPxaB7cXWLd8pCL7SW
    Vault:              Ledger
    ID:                 bip32-ed25519/44'/1729'/0'/0'
    Active:             true
    Allowed Operations: [block endorsement generic]
    Allowed Kinds:      [delegation endorsement origination reveal transaction]
    Public Key Hash:    tz2ByDXtXn3Wj4k6DoJnyKHMA68xJvL1nBmV
    Vault:              Ledger
    ID:                 secp256k1/44'/1729'/0'/1'
```

### List all connected Ledgers

```sh
% signatory-cli ledger list
Path:    IOService:/AppleARMPE/arm-io@10F00000/AppleT810xIO/usb-drd1@2280000/AppleT8103USBXHCI@01000000/usb-drd1-port-hs@01100000/USB2.1 Hub@01100000/AppleUSB20Hub@01100000/AppleUSB20HubPort@01130000/Nano S@01130000/Nano S@0/AppleUserUSBHostHIDDevice
ID:      tz1Qrqpz6bVUgZc5o5qARHB7j2v57z6knm55 / 3944f7a0
Version: TezBake 2.2.11 a6fbd27f
```

## Setup baking with signatory and ledger

Keep tezos-baker app open for the below configurations and when the baker is running.
No prompt will be seen in ledger during signing operations.

```sh
signatory-cli ledger setup-baking [--chain-id <chain_id>] [--main-hwm <hwm>] [--test-hwm <hwm>] [-d <device>] <path>
```

Example:

```sh
signatory-cli ledger setup-baking -d 3944f7a0 "bip32-ed25519/44'/1729'/0'/0'"
```

### Reset high water marks

```sh
signatory-cli ledger set-high-watermark [-d <device>] <hwm>
```

Example:

```sh
signatory-cli ledger set-high-watermark -d 3944f7a0 0
```

## Vault Setup Hints
- You CANNOT import a key to a ledger device
- Making sure that the ledger device is able to work with your linux system is enabled through udev rules. Some examples can be found [here](https://github.com/LedgerHQ/udev-rules)
  - I suggest appending the following to the section for the device you are using:
  `, ACTION=="add", GROUP="{your_user_group}"`
  - The add action is for when you plug in the device and making sure the device has the permissions group you belong to will make sure you don't need to run any commands as a root user

## Key Management
### Setup from fresh install and recovery phrase generation
- Install ledger live, activate the developer mode (in settings -> experimental features) to get the tezos wallet/baking apps made by {whatever company makes them, fill in, possibly Zondax}
- Connect the ledger device to the machine that will be running the node/baker(s)
- Determine the ID of the ledger device
  - You must have signatory and signatory-cli set up. If this has not been done please move onto the signatory setup section and come back

  ```
  ~/signatory$ ./signatory-cli ledger list -c signatory.yaml
  INFO[0000] Initializing vault                            vault=ledger vault_name=ledger
  Path:           0001:0007:00
  ID:             tz1bjnGUjZFH22QSag2dyiKA5P6y24iKoTQx / b0987791
  Version:        TezBake 2.2.13```
  - The first part of the ID is important since it will be used by the signatory.yaml file to identify this ledger
- Get the public key hash from the ledger device
```
~/signatory$ ./signatory-cli list -c signatory.yaml 
INFO[0000] Initializing vault                            vault=ledger vault_name=ledger
Public Key Hash:    tz1Kiak7gwhv6fvcpq9Q9ghjKNuFNYDtUJUG
Vault:              Ledger
ID:                 bip32-ed25519/44'/1729'/0'/0'
Active:             false

Public Key Hash:    tz2F7vTTMvMb2HRywjjjMpftkGDLQKoEkbsr
Vault:              Ledger
ID:                 secp256k1/44'/1729'/0'/1'
Active:             false
```
- Make sure that tezos client can access the ledger through the command `tezos-client list connected ledgers`
- Add funds to account (faucet can normally be found [here](https://teztnets.xyz/))
- Set up ledger for baking (See if you're using the bip32-25519 address you will need to use a command like `./signatory-cli ledger setup-baking bip25519/0h/0h -c signatory.yaml`). You will also need to go to the device and verufy the request to set it up for baking
```
~/signatory$ ./signatory-cli ledger setup-baking bip25519/0h/0h -c signatory.yaml 
INFO[0000] Initializing vault                            vault=ledger vault_name=ledger
Authorized baking for address: tz1Kiak7gwhv6fvcpq9Q9ghjKNuFNYDtUJUG
```
- Make sure to run signatory after adding the correct info to the yaml file (`./signatory serve -c signatory.yaml` after filling in info in signatory.yaml section)
- Add the ledger device to the tezo-client as a delegate for baking (this will also require a device verification, steps found in the tezos-client setup below)

### What you need for ledger in a signatory configuration YAML file
The following is needed in a config file for signatory to know what it is looking for on a ledger nano S
```
# The vaults section is what defines the connection to the yubiHSM
vaults:
    ledger:
    driver: ledger
    config:
      # id: {First part of ledger ID you got from './signatory-cli ledger list'}
      keys:
        - "bip32-ed25519/0'/0'"
        - "secp256k1/0'/1'"
      close_after: 600800s

# This section is for public key hashes to define what is activated IRL
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
## Signatory-cli features for Ledger
Once you have signatory binaries and the ledger set up it is time to test the connection between the hardware and signatory. After completing the setup for the ledger and signatory we can test it by using the signatory-cli command `list`. Here is an example(notice the additional info from when we did it before):
```
~/signatory$ ./signatory-cli list --help
List public keys

Usage:
  signatory-cli list [flags]

Flags:
  -h, --help   help for list

Global Flags:
  -c, --config string   Config file path (default "/etc/signatory.yaml")
      --log string      Log level: [error, warn, info, debug, trace] (default "info")

~/signatory$ ./signatory-cli list -c signatory.yaml
INFO[0000] Initializing vault                            vault=ledger vault_name=ledger
Public Key Hash:    tz1fNiSGiq7X7Br1H5pgPJWJSGouBaRAw8Qb
Vault:              Ledger
ID:                 bip32-ed25519/44'/1729'/0'/0'
Active:             true
Allowed Operations: [block endorsement generic]
Allowed Kinds:      [delegation endorsement reveal transaction]
```
## Final Signatory Verification Test
We can finally see that all the pieces are working together by curling the signatory service and asking for the public key associated with our active public key hash:
`curl http://localhost:6732/keys/tz3c6J47hHmwuasew7Y3HMZzmy7ymDgd6cfy`
The output can be verified by checking the public_keys file in the .tezos-client directory