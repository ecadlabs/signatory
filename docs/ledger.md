---
id: ledger
title: Ledger
---

# Ledger vault

Connect the Ledger device to the system where Signatory is running.
Install the Tezos Wallet and Tezos Baking apps from [Ledger Live](https://www.ledger.com/ledger-live/download).

Note: Developer mode might be required to install the Baking app. See [Ledger Developer mode](https://developers.ledger.com/docs/live-app/developer-mode/#:~:text=To%20activate%20the%20Developer%20mode,Live%20version%202.32%20and%20above.).

:::caution Ledger Nano S end-of-support
Ledger has discontinued support for the Ledger Nano S. If you are using a Nano S with Signatory for baking or signing, you should upgrade to a supported device:

- Ledger Nano S+ or Ledger Nano X (see product pages for current availability)
- A server-grade HSM such as YubiHSM 2 (see `docs/yubihsm.md`)

References: [Ledger Nano S limitations/support](https://support.ledger.com/article/Ledger-Nano-S-Limitations), [Ledger hardware wallets](https://shop.ledger.com/pages/hardware-wallet), [Ledger Nano S Plus](https://shop.ledger.com/products/ledger-nano-s-plus).
:::

:::info Flash/NVRAM duty cycle and proactive replacement for bakers
- The ST secure elements used in Ledger devices specify about 500,000 erase/write cycles per flash page (64-byte pages) and ~30-year data retention. See [BOLOS memory](https://github.com/LedgerHQ/ledger-dev-doc/blob/master/source/userspace/memory.rst), [ST31G480](https://www.st.com/en/secure-mcus/st31g480.html), and [ST31G256 datasheet](https://www.st.com/resource/en/data_brief/st31g256.pdf).
- Older versions of the Tezos Baking app persisted the High Watermark (HWM) to NVRAM after each signed operation, which could accelerate wear. In March–April 2024, the app added a setting to disable HWM persistence and moved HWM tracking to RAM, significantly reducing writes; writes to NVRAM now occur only in limited cases (e.g., clean exit). See the app documentation/README: [LedgerHQ/app-tezos-baking](https://github.com/LedgerHQ/app-tezos-baking).
- Recommendation: Bakers using older Ledger devices (especially those used for baking prior to the 2024 improvements) should proactively upgrade hardware. If you continue to use a Ledger for baking, install the latest Tezos Baking app and consider disabling HWM persistence to minimize flash wear.
:::

## Configuration

| Name        | Type         | Required | Description                                                   |
|-------------|--------------|----------|---------------------------------------------------------------|
| id          | string       | Yes      | Ledger device ID. Uses the first available device if not specified |
| keys        | string array | Yes      | Managed key IDs                                               |
| close_after | duration     | No       | Close the device after a certain period of inactivity         |

### Keys and ID format

Syntax: `derivation/bip32`

Where `bip32` is a [BIP 0032](https://en.bitcoin.it/wiki/BIP_0032) path and
`derivation` is one of the following schemes: `ed25519`, `secp256k1`, `p-256`,
`secp256r1` (alias for `p-256`), `bip25519`, `bip32-ed25519` (alias for
`bip25519`). `bip25519` is a [BIP 0032](https://en.bitcoin.it/wiki/BIP_0032)
compliant scheme; the others use a custom hash chain.

Ledger-specific root `m/44'/1729'` may be omitted.

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

### close_after field in config

Configure this value as required. Because you do not know the time between the blocks assigned to your baker, configure it for at least a few hours to prevent the Ledger device from closing due to inactivity.

Example:

```yaml
close_after: 3600s
```

### Transports

By default, the Ledger vault uses the `usb` transport. Another available transport is `tcp`, used primarily for interaction with the [Speculos](https://github.com/LedgerHQ/speculos)
emulator. It can be enabled using the `transport` option:

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

In addition, the `signatory-cli ledger` command also accepts the `-t`/`--transport` option with the same URL-like syntax:

```sh
signatory-cli ledger --transport 'tcp://127.0.0.1:9999' list
```

## Getting data from Ledger for Signatory configuration using the CLI

Keep the Tezos Wallet app open for the commands below and for signing any wallet transactions.
During every wallet transaction, provide Accept/Reject input on the Ledger device when prompted.

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

### Ledger device lock

Signatory acquires a read lock on the Ledger device while in operation. When the Signatory service is running and has a valid configuration for a Ledger device, the `signatory-cli` binary will encounter the error "ledger: hidapi: failed to open device" when trying to list ledgers. Only one process can acquire a read lock on the Ledger device.

## Set up baking with Signatory and Ledger

Keep the Tezos Baking app open for the configurations below and when the baker is running.
No user interaction is required on the Ledger device during signing operations.

```sh
signatory-cli ledger setup-baking [--chain-id <chain_id>] [--main-hwm <hwm>] [--test-hwm <hwm>] [-d <device>] <path>
```

Example:

```sh
signatory-cli ledger setup-baking -d 3944f7a0 "bip32-ed25519/44'/1729'/0'/0'"
```

### Reset High Watermarks

```sh
signatory-cli ledger set-high-watermark [-d <device>] <hwm>
```

Example:

```sh
signatory-cli ledger set-high-watermark -d 3944f7a0 0
```