---
id: GCP_kms
title: Google Cloud Platform KMS
---
## Alex's Changes for GCP:

#### Note on convention: 
Anything surrounded by curly brackets is a piece of info that will be specific to you. For example {tezos_public_key_hash} will be something on your system resembling `tz1P572ijpP...`

### Introduction to GCP HSM:

They will likely describe their own products far better than we ever could. Some resources are available here
- [HSM Overview](https://cloud.google.com/kms/docs/hsm)
- [KMS Overview](https://cloud.google.com/security-key-management)

### Trade-offs of using GCP HSM: 
To be completed later

### Vault Setup Hints
- TBD

### Key Management
#### Generating a key ring
- First step is to create a key ring (The key ring name and location are required in the signatory configuration)
    - Key rings can be found in the security section of your GCP project (Security -> Key Management)
    - When creating the key a few things are important:
        - Purpose should be "asymmetric sign"
        - Protection level should be "HSM"

#### Custom Role Creation (Reference: https://cloud.google.com/iam/docs/creating-custom-roles)
- Creating a role for a service account:
  - Service accounts are only able to assign permissions from roles instead of individual permissions
- Navigate to the IAM & Admin section in the GCP dashboard -> Roles
- Create a role and name is whatever you like
- Assign the following permissions for an all-in-one role:
    - cloudkms.cryptoKeyVersions.get
    - cloudkms.cryptoKeyVersions.list
    - cloudkms.cryptoKeyVersions.viewPublicKey
    - cloudkms.cryptoKeys.get
    - cloudkms.cryptoKeys.list
    - cloudkms.cryptoKeyVersions.useToSign
    - cloudkms.cryptoKeyVersions.create
    - cloudkms.cryptoKeys.create
    - cloudkms.importJobs.create
    - cloudkms.importJobs.get
    - cloudkms.importJobs.list
    - cloudkms.importJobs.useToImport

#### Service Accounts (Reference: https://cloud.google.com/iam/docs/service-accounts):
Creating a service account from scratch:
- Navigate to the IAM & Admin section in the GCP dashboard -> Service Accounts
- Create a new service account
- Assign your signatory role to the account
- Assign any users you need to the service account
- Create a new key within the service account and download the service account key JSON file to your local machine

#### Connecting your GCP service account credentials to your signatory environment
- This is done through an environment variable:
export GOOGLE_APPLICATION_CREDENTIALS="Your_Credentials_JSON_File"

#### Importing a key into GCP
- You can generate a private key in an air gapped environment and then import it into GCP Key Management using the signatory-cli binary
  - You must have signatory and signatory-cli set up. If this has not been done please move onto the signatory setup section and come back
- The import command is the command that will take your secret key and set up signatory to use it:

```
alexander@debian:~/signatory$ ./signatory-cli import --help
Import Tezos private keys (edsk..., spsk..., p2sk...)

Usage:
  signatory-cli import <pkh> [flags]

Flags:
  -h, --help              help for import
  -o, --opt string        Options to be passed to the backend. Syntax: key:val[,...]
      --password string   Password for private key(s)
      --vault string      Vault name for importing

Global Flags:
  -c, --config string   Config file path (default "/etc/signatory.yaml")
      --log string      Log level: [error, warn, info, debug, trace] (default "info")
```
- An example command and the associated output are as follows:
```
./signatory-cli import -c signatory.yaml --vault kms p2esk28hoUE2J88QNFj2aDX2pjzL7wcVh2g8tkEwtWWguby9M3FHUgSbzvF2Sd7wQ4Kd8crFwvto6gF3otcBuo4T
INFO[0000] Initializing vault                            vault=cloudkms vault_name=kms
Enter Password: 
INFO[0002] Requesting import operation                   pkh=tz3be5v4ZWL3zQYUZoLWJQy8P3H6RJryVVXn vault=CloudKMS vault_name=projects/signatory-testing/locations/europe-north1/keyRings/sign-ring
INFO[0008] Successfully imported                         key_id=projects/signatory-testing/locations/europe-north1/keyRings/sign-ring/cryptoKeys/signatory-imported-215FwcXxhLdlr9IYwzA31vwANmy/cryptoKeyVersions/1 pkh=tz3be5v4ZWL3zQYUZoLWJQy8P3H6RJryVVXn vault=CloudKMS vault_name=projects/signatory-testing/locations/europe-north1/keyRings/sign-ring
```

#### What you need for GCP in a signatory configuration YAML file
The following is needed in a config file for signatory to know what it is looking for on a yubiHSM
```
# The vaults section is what defines the connection to the yubiHSM
vaults:
  cloudkms:
    driver: cloudkms
    config:
      project: {GCP Project Name}
      location: {GCP Project Region/Location}
      key_ring: {GCP Keyring Name}

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

### Signatory-cli features for GCP KMS
Once you have signatory binaries and the appropriate GCP pieces set up it is time to test the connection between the hardware and signatory. After completing the setup for the HSM and signatory we can test it by using the signatory-cli command `list`. Here is an example:
```
alexander@debian:~/signatory$ ./signatory-cli list --help
List public keys

Usage:
  signatory-cli list [flags]

Flags:
  -h, --help   help for list

Global Flags:
  -c, --config string   Config file path (default "/etc/signatory.yaml")
      --log string      Log level: [error, warn, info, debug, trace] (default "info")
      
alexander@debian:~/signatory$ ./signatory-cli list -c signatory.yaml
INFO[0000] Initializing vault                            vault=cloudkms vault_name=cloudkms
Public Key Hash:    tz3c6J47hHmwuasew7Y3HMZzmy7ymDgd6cfy
Vault:              CloudKMS
ID:                 projects/signatory-testing/locations/northamerica-northeast1/keyRings/alex-key-ring-first/cryptoKeys/alex-HSM-Key-1/cryptoKeyVersions/1
Active:             true
Allowed Operations: [block endorsement generic]
Allowed Kinds:      [delegation endorsement reveal transaction]
```

### Final Signatory Verification Test
We can finally see that all the pieces are working together by curling the signatory service and asking for the public key associated with our active public key hash:
`curl http://localhost:6732/keys/tz3c6J47hHmwuasew7Y3HMZzmy7ymDgd6cfy`

The output can be verified by checking the public_keys file in the .tezos-client directory