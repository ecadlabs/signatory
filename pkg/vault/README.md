# Google Cloud Platform configuration
Service account used with Signatory should have following permissions. It may be achived by using custom roles (see https://console.cloud.google.com/iam-admin/roles)

## Basic permissions
* cloudkms.cryptoKeyVersions.get
* cloudkms.cryptoKeyVersions.list
* cloudkms.cryptoKeyVersions.viewPublicKey
* cloudkms.cryptoKeys.get
* cloudkms.cryptoKeys.list

## Sign
* cloudkms.cryptoKeyVersions.useToSign

## Import
* cloudkms.cryptoKeyVersions.create
* cloudkms.cryptoKeys.create
* cloudkms.importJobs.create
* cloudkms.importJobs.get
* cloudkms.importJobs.list
* cloudkms.importJobs.useToImport