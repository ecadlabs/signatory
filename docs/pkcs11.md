---
id: pkcs11
title: PKCS#11
---

# PKCS#11 Vault

## Configuration

|||||
|--- |--- |--- |--- |
|Name|Type|Required|Description|
|library_path|string|✅|Library Path|
|pin|string|✅|User PIN|
|slot|string||Slot ID|
|label|string||Limit key search to the specified label (use in case of multiple key pairs in the same token)|
|object_ih|hex||Limit key search to the specified object ID (use in case of multiple key pairs in the same token)|

**Note**: If the token contains multiple key pairs, every pair must have unique label or ID shared between private and public parts.

### Example

```yaml
library_path: /opt/homebrew/lib/softhsm/libsofthsm2.so
pin: 1234
slot: 0x4d0b85a2
label: TestKey
```

## Environment variables

* `PKCS11_PATH`
* `PKCS11_PIN`
* `PKCS11_SLOT`
* `PKCS11_LABEL`
* `PKCS11_OBJECT_ID`
