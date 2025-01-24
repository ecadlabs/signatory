---
id: pkcs11
title: PKCS#11 (AWS CloudHSM compatible)
---

# PKCS#11 Vault

> **Note**: The PKCS#11 configuration is commonly used for signing with an AWS Cloud HSM backend. Ensure that your AWS Cloud HSM setup is properly configured and the required libraries are available.

## Configuration

| Field                      | Type                               | Required | Description                                                  |
| -------------------------- | ---------------------------------- | -------- | ------------------------------------------------------------ |
| library_path               | string                             | ✅        | Library path. If not specified then `PKCS11_PATH` environment variable value will be used instead. |
| slot                       | unsigned integer                   |          | Slot ID. Is both the field and `PKCS11_SLOT` environment variable are missed then the first slot with an initialised token will be used. |
| pin                        | string                             | ✅        | User PIN.  If not specified then `PKCS11_PIN` environment variable value will be used instead. |
| keys                       | sequence of `Key Pair` (see below) |          | Key list. Use all available keys if not specified (see `public_keys_search_options` description) |
| public_keys_search_options |                                    |          | Automatic key pair discovery options (see below)             |

### Key Pair

| Field            | Type                     | Required | Description                                                  |
| ---------------- | ------------------------ | -------- | ------------------------------------------------------------ |
| private          | `Key Config` (see below) |          | Private key locator.                                         |
| public           | `Key Config`             |          | Public key locator.                                          |
| public_value     | Base58 string            |          | Public key value.                                            |
| extended_private | boolean                  |          | Try to read the public key data from the private key object. In some PKCS#11 implementations private key objects have `EC_POINT` attribute. |

> **Note**: `public_value` takes precedence over `public`. If none of `public` and `public_value` fields are present then the private key locator `Key Config` will be reused.

### Key Config

| Field | Type   | Required | Description  |
| ----- | ------ | -------- | ------------ |
| label | string |          | Object label |
| id    | hex    |          | Object ID    |

### Public Keys Search Options

| Field            | Type    | Required | Description                                                  |
| ---------------- | ------- | -------- | ------------------------------------------------------------ |
| match_label      | boolean |          | Find the corresponding public key by matching label.         |
| match_id         | boolean |          | Find the corresponding public key by matching ID.            |
| extended_private | boolean |          | Try to read the public key data from the private key object. |

> **Note**: if the whole object is missing then all options will be assumed as **true**

### Environment Variables

| Variable    | Description  |
| ----------- | ------------ |
| PKCS11_PATH | Library path |
| PKCS11_SLOT | Slot ID      |
| PKCS11_PIN  | User PIN     |

## Examples

### Automatic discovery

```yaml
library_path: /usr/lib/hsmdriver/libhsmdriver.so
pin: user_pin
```

### Manual Configuration

```yaml
library_path: /usr/lib/hsmdriver/libhsmdriver.so
slot: 0
pin: user_pin
  keys:
    - private:
        label: PrivateKey0
      public:
        label: PublicKey0
    - private:
        label: Key1
      # Use public key with the same label `Key1'
    - private:
        id: 1234abcd
      public_value: edpkuXdPrbYEu5x54NaZEzaSHzwi5Tis5NBHrs58AMJXf4gS4iz5eQ
    - private:
        label: Key2
      extended_private: true # Read the public key from the private object
```
