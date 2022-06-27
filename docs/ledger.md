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
| close_after | duration     |          | Close device after a certain period of inactivity             |

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
# Name of vault
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
