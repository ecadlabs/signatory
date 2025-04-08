---
id: pkcs11
title: PKCS#11 (AWS CloudHSM compatible)
---

# PKCS#11 Vault

:::note
The PKCS#11 configuration is commonly used for signing with an AWS Cloud HSM backend. Ensure that your AWS Cloud HSM setup is properly configured and the required libraries are available.
:::

:::danger[AWS CloudHSM Deprecation Notice]
AWS CloudHSM Client SDK 5.8.0 and earlier versions are deprecated. Users should upgrade to Client SDK 5.9 or higher. Additionally, as of January 1, 2024, AWS CloudHSM has deprecated Triple DES and RSA PKCS#1 v1.5 padding in FIPS-compliant clusters. See [AWS CloudHSM deprecation notice](https://docs.aws.amazon.com/cloudhsm/latest/userguide/deprecated.html) for details.
:::

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
| extended_private | boolean                  |          | Try to read the public key data from the PKCS#11 object representing the private key. The private key material itself remains secure within the HSM, but in some implementations (like AWS CloudHSM), the object referencing a private key contains an `EC_POINT` attribute with the corresponding public key data. |

:::info
`public_value` takes precedence over `public`. If none of `public` and `public_value` fields are present then the private key locator `Key Config` will be reused.
:::

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
| extended_private | boolean |          | Retrieve public key data from the PKCS#11 object that represents the private key. This is critical for AWS CloudHSM which stores the EC_POINT attribute (public key data) as an attribute of the private key object handle. The private key material itself always remains secure within the HSM. |

:::info
If the whole object is missing then all options will be assumed as **true**
:::

### Environment Variables

| Variable    | Description  |
| ----------- | ------------ |
| PKCS11_PATH | Library path |
| PKCS11_SLOT | Slot ID      |
| PKCS11_PIN  | User PIN     |

## Automatic Key Discovery

Signatory can automatically discover and use keys stored in the HSM without manual configuration. This happens when the `keys` field is omitted from configuration. 

How automatic discovery works:

1. Signatory queries the HSM for all PKCS#11 objects representing private keys
2. For each private key reference, it attempts to find the matching public key using the configured search options
3. Successfully matched key pairs are made available for signing

The search behavior is controlled by `public_keys_search_options`:

- `match_label: true` - Find public key with same label as private key
- `match_id: true` - Find public key with same ID as private key  
- `extended_private: true` - Extract public key data from the PKCS#11 object representing the private key (AWS CloudHSM specific)

By default, all three options are enabled. For AWS CloudHSM, the `extended_private` option is particularly important as it allows Signatory to access the public key information (EC_POINT attribute) stored as an attribute of the private key's PKCS#11 object, eliminating the need to locate separate public key objects. The actual private key material always remains secure within the HSM's hardware boundary.

## Examples

:::note
In the examples below, identifiers like `aws-hsm` or `softhsm` are arbitrary vault names you choose. The `driver: pkcs11` setting is what actually determines that these use the PKCS11 implementation.
:::

### Automatic discovery

```yaml
vaults:
  aws-hsm:  # This name is arbitrary - you choose it
    driver: pkcs11  # This specifies the PKCS11 implementation
    library_path: /opt/cloudhsm/lib/libcloudhsm_pkcs11.so
    pin: "user:password"
    # No keys specified - will automatically discover all available keys
    # All search options enabled by default
```

### Custom search options

```yaml
vaults:
  custom-hsm:  # Different name, same driver
    driver: pkcs11
    library_path: /opt/cloudhsm/lib/libcloudhsm_pkcs11.so
    pin: "user:password"
    # Configure how public keys are matched with private keys
    public_keys_search_options:
      match_label: true
      match_id: false
      extended_private: true  # AWS CloudHSM specific
```

### Manual Key Configuration

```yaml
vaults:
  softhsm:
    driver: pkcs11
    library_path: /usr/lib/softhsm/libsofthsm2.so
    slot: 0
    pin: "1234"
    keys:
      # Example 1: Specify both private and public keys by label
      - private:
          label: "PrivateKey1"
        public:
          label: "PublicKey1"
      
      # Example 2: Public key with same label as private key
      - private:
          label: "Key2"
      
      # Example 3: Using key ID instead of label
      - private:
          id: "1234abcd"
        public_value: edpkuXdPrbYEu5x54NaZEzaSHzwi5Tis5NBHrs58AMJXf4gS4iz5eQ
      
      # Example 4: AWS CloudHSM style - public key embedded in private key
      - private:
          label: "CloudHSMKey"
        extended_private: true
```
