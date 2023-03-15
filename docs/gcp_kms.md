---
id: gcp_kms
title: GCPKMS
---

# **Google Cloud Platform configuration**

Some resources are available here
- [HSM Overview](https://cloud.google.com/kms/docs/hsm)
- [KMS Overview](https://cloud.google.com/security-key-management)

Create a new project or use an existing project and the service accounts used with Signatory should have the following permissions. It may be achieved by using custom roles (see [https://console.cloud.google.com/iam-admin/roles](https://console.cloud.google.com/iam-admin/roles)) \
Project name is required in the signatory config.

## **Basic permissions**

* `cloudkms.cryptoKeyVersions.get`
* `cloudkms.cryptoKeyVersions.list`
* `cloudkms.cryptoKeyVersions.viewPublicKey`
* `cloudkms.cryptoKeys.get`
* `cloudkms.cryptoKeys.list`

## **Sign**

* `cloudkms.cryptoKeyVersions.useToSign`

## **Import**

* `cloudkms.cryptoKeyVersions.create`
* `cloudkms.cryptoKeys.create`
* `cloudkms.importJobs.create`
* `cloudkms.importJobs.get`
* `cloudkms.importJobs.list`
* `cloudkms.importJobs.useToImport`

## **Configuration parameters**

Below are the configuration fields which are required for Signatory.

|||||
|--- |--- |--- |--- |
|Name|Type|Required|Description|
|application_credentials|string|OPTIONAL|Path to the GCP application token JSON file (overrides GOOGLE_APPLICATION_CREDENTIALS environment variable)|
|application_credentials_data|string|OPTIONAL|GCP application token JSON data (overrides application_credentials)|
|project|string|✅|Project name|
|location|string|✅|Location|
|key_ring|string|✅|Key ring name|

## **Key Management**

Under `key management` create a new `key-ring` with any location and create a key with `purpose` as `Asymmetric-sign` and `protection level` as `HSM`.

The key-ring name and location are required in the signatory configuration.

- Key rings can be found in the security section of your GCP project (Security -> Key Management)
- When creating the key a few things are important:
  - Purpose should be "asymmetric sign"
  - Protection level should be "HSM"

## **Application Access:**

The below steps are for providing signatory with the permissions to access the google cloud account Key Management.

* Select `IAM & ADMIN` from the menu and select `Service accounts`. Create a new service account or use an existing one with all the above permissions (Get, Sign & Import) granted.
* Select the created/existing service account and within that create a new key and a prompt to download the application credentials will appear, select the JSON format.
* The downloaded JSON file is needed in signatory config or can be assigned to the below environment variable.

## **Environment variables**

`cloudkms` backend accepts GCP's standard `GOOGLE_APPLICATION_CREDENTIALS` environment variable

```sh
export GOOGLE_APPLICATION_CREDENTIALS="signatory-testing-a7sdfew625aecb.json"
```

## **Getting a PKH**

```sh
signatory % ./signatory-cli list -c /etc/s.yaml
Public Key Hash:    tz3fK7rVYSg2HTEAmUYdfjJWSDGfsKrxH3xQ
Vault:              CloudKMS
ID:                 projects/signatory-testing/locations/europe-north1/keyRings/sigy-key/cryptoKeys/sigyhsm/cryptoKeyVersions/4
Status:             FOUND_NOT_CONFIGURED
*DISABLED*
```

**Update signatory.yaml config with the PKH:**

```yaml
server:
  address: :6732
  utility_address: :9583

vaults:
  gcp:
    driver: cloudkms
    config:
      project: <gcp_project>
      location: <gcp_region>
      key_ring: <key_ring_name>
      application_credentials: <credentials_file_path>
tezos:
  tz3fK7rVYSg2HTEAmUYdfjJWSDGfsKrxH3xQ:
    log_payloads: true
    allow:
      block:
      endorsement:
      preendorsement:
      generic:
        - transaction
```

## **Key Import:**

Users can generate a private key in an air gap environment and then import it into GCP Key Management using `signatory-cli` binary. Below are the steps to do that.

1. Build `signatory-cli` binary using `make signatory-cli`. You need `Golang version 1.15` or later.

2. Use the below command to import the generated private into GCP Key Management. Only `Elliptic Curve P-256 - SHA256` `Digest` is supported now. Below sample key is taken from `signatory/docs/yubihsm.md`

```sh
% ./signatory-cli import -c signatory.yaml --vault kms

INFO[0000] Initializing vault                            vault=cloudkms vault_name=kms
Enter secret key: 
Enter Password: 
Enter Password: INFO[0002] Requesting import operation                   pkh=tz3be5v4ZWL3zQYUZoLWJQy8P3H6RJryVVXn vault=CloudKMS vault_name=projects/signatory-testing/locations/europe-north1/keyRings/sign-ring
INFO[0008] Successfully imported                         key_id=projects/signatory-testing/locations/europe-north1/keyRings/sign-ring/cryptoKeys/signatory-imported-215FwcXxhLdlr9IYwzA31vwANmy/cryptoKeyVersions/1 pkh=tz3be5v4ZWL3zQYUZoLWJQy8P3H6RJryVVXn vault=CloudKMS vault_name=projects/signatory-testing/locations/europe-north1/keyRings/sign-ring
```

## Custom Role Creation 
(Reference: https://cloud.google.com/iam/docs/creating-custom-roles)
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