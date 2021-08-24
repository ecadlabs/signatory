# Ledger vault

## Configuration

| Name        | Type         | Description                                                   |
| ----------- | ------------ | ------------------------------------------------------------- |
| id          | string       | Ledger Device ID. Use first available device if not specified |
| keys        | string array | Managed key IDs                                               |
| close_after | duration     | Close device after a certain period of inactivity             |

### Key ID

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
id: 3944f7a0
keys:
    - "bip25519/0'/0'"
    - "secp256k1/0'/1'"
```

## Command line interface

### List all connected Ledgers

```
signatory-cli ledger list
```

Example output:

```
Path:  		IOService:/AppleARMPE/arm-io@10F00000/AppleT810xIO/usb-drd1@2280000/AppleT8103USBXHCI@01000000/usb-drd1-port-hs@01100000/USB2.1 Hub@01100000/AppleUSB20Hub@01100000/AppleUSB20HubPort@01130000/Nano S@01130000/Nano S@0/AppleUserUSBHostHIDDevice
ID:     	tz1Qrqpz6bVUgZc5o5qARHB7j2v57z6knm55 / 3944f7a0
Version:	TezBake 2.2.11 a6fbd27f
```

### Setup baking

```
signatory-cli ledger setup-baking [--chain-id <chain_id>] [--main-hwm <hwm>] [--test-hwm <hwm>] [-d <device>] <path>
```

Example:

```sh
signatory-cli ledger setup-baking -d 3944f7a0 "bip32-ed25519/44'/1729'/0'/0'"
```

### Reset high water marks

```
signatory-cli ledger set-high-watermark [-d <device>] <hwm>
```

Example:

```sh
signatory-cli ledger set-high-watermark -d 3944f7a0 0
```
