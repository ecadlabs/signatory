# AWS KMS Configuration

Create an asymetric key with usage as "sign and verify" in your AWS account. 
Note: Support for "ECC_SECG_P256K1" spec is not there yet.

Search for IAM and create a user with "Programmatic access" for Signatory to access the key resources. Save the details at the end which will be given only once on creation of the user.

## AWS KMS backend

Below are the minimum configuration required.

```sh
config:
      user_name: signatory-test
      kms_key_id: ab717a73-4cb5-4d66-b531-9e389bf5feb6
      access_key_id: AKIAWXBZ6RID4YZT5U6Q
      secret_access_key: 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
      region: us-east-2
```

### Configuration parameters

Name | Type | Required | Description
-----|------|:--------:|------------
user_name | string |✅| IAM user name
kms_key_id | string |✅| KeyId of the key from AWS KMS to be used for signing
access_key_id | string | ✅ | IAM user detail
secret_access_key | string | ✅ | IAM user detail
region | string | ✅ | Region where key is created
