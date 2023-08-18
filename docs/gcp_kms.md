---
id: gcp_kms
title: GCPKMS
---

# **Google Cloud Platform configuration**

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

## **Application Access:**

Providing Signatory with the permissions to access GCP KMS will differ depending on whether or not Signatory is running inside or outside of GCP. 
One thing that each method has in common is the creation of a Service Account:

* Select `IAM & ADMIN` from the menu and select `Service accounts`. Create a new service account or use an existing one with all the above permissions (Get, Sign & Import) granted.

### **Authenticating with the Service Account from outside GCP:**

* Select the created/existing service account and within that create a new key and a prompt to download the application credentials will appear, select the JSON format.
* The downloaded JSON file is needed in signatory config or can be assigned to the below environment variable.

```sh
export GOOGLE_APPLICATION_CREDENTIALS="signatory-testing-a7sdfew625aecb.json"
```

### **Authenticating with the Service Account from GCP VM:**

Do not download the service account credentials and place them on Signatory's file system, and do not use `GOOGLE_APPLICATION_CREDENTIALS` env var. Instead, edit the VM specifications for `Identity and API access` such that it selects the IAM Service Account.

### **Authenticating with the Service Account from GKE pod:**

Do not download the service account credentials and place them on Signatory's file system, and do not use `GOOGLE_APPLICATION_CREDENTIALS` env var. Best practice is to [use Workload Identity](https://cloud.google.com/kubernetes-engine/docs/how-to/workload-identity)  In short:

* enable Workload Identity on the cluster
* create a kubernetes Service Account and bind it to the IAM Service Account
* annotate the kubernetes Service Account with the email address of the IAM Service Account
* update the pod spec to include the `serviceAccountName` field, this is the name of the kubernetes Service Account

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