# Google Cloud Platform

## Google Cloud Platform configuration

Service account used with Signatory should have following permissions. It may be achived by using custom roles (see https://console.cloud.google.com/iam-admin/roles)

### Basic permissions
* `cloudkms.cryptoKeyVersions.get`
* `cloudkms.cryptoKeyVersions.list`
* `cloudkms.cryptoKeyVersions.viewPublicKey`
* `cloudkms.cryptoKeys.get`
* `cloudkms.cryptoKeys.list`

### Sign
* `cloudkms.cryptoKeyVersions.useToSign`

### Import
* `cloudkms.cryptoKeyVersions.create`
* `cloudkms.cryptoKeys.create`
* `cloudkms.importJobs.create`
* `cloudkms.importJobs.get`
* `cloudkms.importJobs.list`
* `cloudkms.importJobs.useToImport`

## Google Cloud KMS backend

### Configuration parameters

Name | Type | Required | Description
-----|------|:--------:|------------
application_credentials | string | | Path to the GCP application token JSON file (overrides `GOOGLE_APPLICATION_CREDENTIALS` environment variable)
application_credentials_data | string | | GCP application token JSON data (overrides `application_credentials`)
project | string | ✅ | Project name
location | string | ✅ | Location
key_ring | string | ✅ | Key ring name

### Environment variables

`cloudkms` backend accepts GCP's standard `GOOGLE_APPLICATION_CREDENTIALS` environment variable

```sh
export GOOGLE_APPLICATION_CREDENTIALS=signatory-testing-a7fd9625aecb.json
```

## Import options

Name | Type | Description
-----|------|------------
name | string | New key name. Otherwise will be auto generated.