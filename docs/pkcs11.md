---
id: pkcs11
title: PKCS#11
---

# PKCS#11 Vault

## Configuration

| Field        | Type                               | Required | Description                                                  |
| ------------ | ---------------------------------- | -------- | ------------------------------------------------------------ |
| library_path | string                             | ✅        | Library path. Empty value means use `PKCS11_PATH` environment variable. |
| slots        | integer to string mapping          | ✅        | Configured slots with corresponding user PINs. Empty value means use `PKCS11_SLOTx_PIN` environment variable. |
| keys         | sequence of `Key Pair` (see below) | ✅        | Key list.                                                    |

### Key Pair

| Field        | Type                     | Required | Description         |
| ------------ | ------------------------ | -------- | ------------------- |
| private      | `Key Config` (see below) | ✅        | Private key locator |
| public       | `Key Config`             |          | Public key locator  |
| public_value | Base58                   |          | Public key value    |

**Note**: `public_value` takes precedence over `public`. If none of `public` and `public_value` fields are present then the private key locator will be reused.

### Key Config

| Field     | Type    | Required | Description                                                  |
| --------- | ------- | -------- | ------------------------------------------------------------ |
| slot      | integer | ✅        | Configured slot ID.                                          |
| label     | string  |          | Limit key search to the specified label (use in case of multiple key pairs in the same token). |
| object_id | hex     |          | Limit key search to the specified object ID (use in case of multiple key pairs in the same token). |

### Example

```yaml
library_path: /usr/lib/softhsm/libsofthsm2.so
slots:
  0: 1234
  # Use `PKCS11_SLOT1_PIN` environment variable
  1:
  2: 5678
  3: abcd
keys:
  - private:
      # Locate private key in slot 0
      slot: 0
    public:
      # Locate public key in slot 1
      slot: 1
  - private:
      # Locate private key in slot 2 with label TestKey
      slot: 2
      label: TestKey
    # Locate public key in slot 2 with label TestKey
  - private:
      slot: 3
    # Use the value below
    public_value: edpkuXdPrbYEu5x54NaZEzaSHzwi5Tis5NBHrs58AMJXf4gS4iz5eQ
```
