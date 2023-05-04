---
id: aws_kms
title: AWSKMS
---


# AWS KMS Configuration

Create an asymmetric key with usage as "sign and verify" in your AWS account.

Search for IAM and create a user with "Programmatic access" for Signatory to access the key resources. Save the details at the end which will be given only once on creation of the user.

## AWS KMS backend

Below is the minimum configuration required.

```yaml
vaults:
  aws:
    driver: awskms
    config:
      user_name: <iam_username>
      access_key_id: <aws_access_key_id>
      secret_access_key: <aws_secret_access_key>
      region: <aws_region>
```

### Configuration parameters

Name | Type | Required | Description
-----|------|:--------:|------------
user_name | string |✅| IAM user name
access_key_id | string | OPTIONAL | IAM user detail
secret_access_key | string | OPTIONAL | IAM user detail
region | string | ✅ | Region where key is created

The fields `access_key_id` & `secret_access_key` can be set in the environment variables `AWS_ACCESS_KEY_ID` & `AWS_SECRET_ACCESS_KEY` respectively.

## Importing a key into AWS

The Import command is not available for AWS as there is no support for asymmetric keys in AWS KMS. (Ref: <https://docs.aws.amazon.com/kms/latest/developerguide/importing-keys.html>) 

## Key generation in AWS

To generate a new private key withing AWS, you must:

- Open up the KMS section of the AWS management console and click on "Customer Managed Keys"
  - Click create key and make sure it contains the following:
    - Asymmetric type
    - Sign and Verify usage
    - ECC_NIST_P256 key spec
    - Single Region
  - Ensure that the users who will need to access the key are added to the usage permissions list and create

## Example Configuration for the AWS KMS vault in Signatory

This example shows a Signatory vault configuration for AWS KMS. Text in `{}` must be replaced, for example, `{AWS_User_Name}` should be replaced with your AWS username.


```
vaults:
  # Name is used to identify backend during import process
  awskms:
    driver: awskms
    config:
      user_name: {AWS_User_Name}
      access_key_id: {Access_Key_ID_In_AWS_User_Profile}
      secret_access_key: {Secret_access_Key_ID_In_AWS_User_Profile}
      region: {AWS_Region}
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

### Signatory-cli features for AWS KMS

Once you have Signatory binaries and the appropriate AWS pieces set up, it is time to test the connection between the hardware and Signatory. After completing the setup for the key and Signatory we can test it by using the signatory-cli command `list`. Here is an example:
```
$ ./signatory-cli list --help
List public keys
Usage:
  signatory-cli list [flags]
Flags:
  -h, --help   help for list
Global Flags:
  -c, --config string   Config file path (default "/etc/signatory.yaml")
      --log string      Log level: [error, warn, info, debug, trace] (default "info")
      
$ ./signatory-cli list -c signatory.yaml
INFO[0000] Initializing vault                            vault=awskms vault_name=awskms
Public Key Hash:    tz3WxgnteyTpM5YzJSTFFtnNYB8Du31gf3bQ
Vault:              AWSKMS
ID:                 arn:aws:kms:us-east-2:461830523399:key/038ec90c-1809-4320-9dc8-9cb05a8ef5bb
Active:             true
Allowed Operations: [block endorsement generic]
Allowed Kinds:      [delegation endorsement reveal transaction]
```

### Final Signatory Verification Test
We can finally see that all the pieces are working together by curling the Signatory service and asking for the public key associated with our active public key hash:
`curl http://localhost:6732/keys/tz3WxgnteyTpM5YzJSTFFtnNYB8Du31gf3bQ`

The output can be verified by checking the public_keys file in the .tezos-client directory