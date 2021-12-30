---
id: AWS_kms
title: Signatory AWS KMS Vault
---



## Introduction to AWS KMS:

They will likely describe their own products far better than we ever could. Some resources are available here
- [KMS Overview](https://docs.aws.amazon.com/kms/latest/developerguide/overview.html)
- [Keys and Management Overview](https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#key-mgmt)

### AWS Key provisioning hints

:::warning Do your research on AWS KMS
You are trusting the AWS KMS product when you use this feature. The following hints are provided to get you started, but the responsibility of understanding the AWS KMS is yours.
:::

#### Key generation in AWS

To generate a new private key withing AWS, you must:

- Open up the KMS section of the AWS management console and click on "Customer Managed Keys"
  - Click create key and make sure it contains the following:
    - Asymmetric type
    - Sign and Verify usage
    - ECC_NIST_P256 key spec
    - Single Region
  - Ensure that the users who will need to access the key are added to the usage permissions list and create

#### Importing a key into AWS
- You can generate a private key in an external environment and then import it into AWS using this [guide](https://docs.aws.amazon.com/kms/latest/developerguide/importing-keys.html)


### Configuring the AWS KMS vault in signatory

This example shows a signatory vault configuration for AWS KMS. Text in `{}` must be replace, for example, `{AWS_User_Name}` should be replaced with your AWS username.


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
  tz3WxgnteyTpM5YzJSTFFtnNYB8Du31gf3bQ:
    # Setting `log_payloads` to `true` will cause Signatory to log operation
    # payloads to `stdout`. This may be desirable for audit and investigative
    # purposes.
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

Once you have signatory binaries and the appropriate AWS pieces set up, it is time to test the connection between the hardware and signatory. After completing the setup for the key and signatory we can test it by using the signatory-cli command `list`. Here is an example:
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

<!-- This section should be moved to its own page, and not duplicated in every Vault documentation page -->
### Tezos Client Setup

Adding the information generated in any vault to the tezos-client is done in a single command, it is as follows:

`tezos-client import secret key {name_you_choose} http://localhost:6732/{your_public_key_hash}`

Using the same pkh as above an example command would look like:

`tezos-client import secret key {name_you_chose} http://localhost:6732/tz3WxgnteyTpM5YzJSTFFtnNYB8Du31gf3bQ`

This should produce the output: `Tezos address added: tz3WxgnteyTpM5YzJSTFFtnNYB8Du31gf3bQ`

Making the added PKH a delegate to begin baking/endorsing is achieved through this command (node/baker/endorser should be running already):

`tezos-client register key {name_you_chose} as delegate`

After the above command is accepted in the chain then if you navigate to a block explorer you should be able to see your account

### Final Signatory Verification Test
We can finally see that all the pieces are working together by curling the signatory service and asking for the public key associated with our active public key hash:
`curl http://localhost:6732/keys/tz3WxgnteyTpM5YzJSTFFtnNYB8Du31gf3bQ`

The output can be verified by checking the public_keys file in the .tezos-client directory
