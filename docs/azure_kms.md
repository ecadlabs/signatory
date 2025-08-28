---
id: azure_kms
title: AzureKMS
---

# Azure Key Vault

The goal of this guide is to configure Signatory to use an Azure Key Vault as a signing backend.

To setup Azure Key Vault as a signing backend for Signatory, you will need:

* An active Azure subscription
* The [Azure CLI](https://docs.microsoft.com/en-us/cli/azure/?view=azure-cli-latest) installed and configured on your computer.

## **Azure setup**

You will need to create several Azure resources, and copy configuration into the signatory config file. Let's begin.

This guide uses the `az` cli command to create all required resources. For each command, you will get a json formatted result, or an error.

### **Log in**

```sh
az login
```

### **Create an Azure resource group.**

You need to specify the location you want your Signatory to be located. This is up to you. The closer to your baker the better, but other criteria may be important to you.

```sh
az group create \
    --name RESOURCE_GROUP \
    --location LOCATION
```

Example:

```sh
az group create --name "signatory" --location "canadaeast"
```

### **Create a new Key Vault, with HSM enabled**

Next we will create a new Key Vault within our newly created resource group.

```sh
az keyvault create \
    --name KEYVAULT_NAME \
    --resource-group RESOURCE_GROUP \
    --sku "premium"
```

Example:

```sh
az keyvault create --name "sigy" --resource-group "sigy" --sku "premium"
```

The `--sku` argument must be set to premium if you want to have your keys stored in a HSM.

Take note of the returned values of `properties.vaultUri` and `properties.tenantId`, these will be used later in the Signatory configuration.

### **Create a Service Principal for authentication**

This document describes a service principal creation flow and a backend configuration for a key-based authentication. Alternatively, you can use client secret-based authentication but it's not recommended.

You will need `openssl` to manipulate keys and certificates.

#### **Generate a client certificate**

```sh
openssl req -newkey rsa:4096 -nodes -keyout "service-principal.key" -out "service-principal.csr"
```

#### **Sign a certificate**

```sh
openssl x509 -signkey "service-principal.key" -in "service-principal.csr" -req -days 365 -out "service-principal.crt"
```

Now you can safely delete the request file (`.csr`).

**Note:** If running signatory in docker then the service-principal.crt should be within the docker. The full path of service-principal.crt within the container is a Signatory configuration file value.

#### **Create a Service Principal for authentication**

Next we need to create a "service principal" resource (also known as a "service account" or a "App Registration").

This is the credential that allows Signatory to authenticate and work with the Azure Key Vault service.

```sh
az ad sp create-for-rbac \
    -n APP_NAME
    --cert "@CERT_FILE"
```

Example:

```sh
az ad sp create-for-rbac -n "signatory" --cert "@service-principal.crt"
```

Example output:

```sh
Changing "sigy" to a valid URI of "http://sigy", which is the required format used for service principal names
Certificate expires 2020-10-24 16:00:14+00:00. Adjusting SP end date to match.
Creating a role assignment under the scope of "/subscriptions/be273d20-6dc1-4bbc-ab26-15d082cca908"
  Retrying role assignment creation: 1/36
  Retrying role assignment creation: 2/36
  Retrying role assignment creation: 3/36
  Retrying role assignment creation: 4/36
{
  "appId": "d5ccc5ea-8a1f-4dc1-9673-183a4c85e280",
  "displayName": "sigy",
  "name": "http://sigy",
  "password": null,
  "tenant": "50c46f11-1d0a-4c56-b468-1bcb03a8f69e"
}
```
Take note of the returned value of `appId`, it is used in subsequent steps, and later in the Signatory configuration.


#### **Create a PKCS #12 file (the Microsoft way)**

This method uses [PKCS #12](https://en.wikipedia.org/wiki/PKCS_12) container file for keeping a self-signed certificate along with the corresponding private key in one bundle. The certificate's hash is needed for the authentication.

```sh
openssl pkcs12 -export -out "service-principal.pfx" -inkey "service-principal.key" -in "service-principal.crt"
```

Now you can safely delete the certificate file (`.csr`).

#### **Get certificate hash from AD**

Alternatively, you can get back a certificate hash

```sh
az ad sp credential list --id APPID --cert
```

Example:

```sh
az ad sp credential list --id "d5ccc5ea-8a1f-4dc1-9673-183a4c85e280" --cert
```

Example output:

```json
[
  {
    "additionalProperties": null,
    "customKeyIdentifier": "6B7HDJ60582104C37600CC237555E7517F5B394C",
    "endDate": "2020-10-24T16:00:13+00:00",
    "keyId": "172bb0bf-77d3-49ud-9725-a642d768tm47",
    "startDate": "2019-11-06T17:06:56.249417+00:00",
    "type": "AsymmetricX509Cert",
    "usage": "Verify",
    "value": null
  }
]
```

The `customKeyIdentifier` contains the certificate's SHA-1 hash (called a thumbprint in Azure documentation). The thumbprint of the certificate can also be found in Azure portal, through Active Directory -> App Registrations -> Client Credentials.

You don't need the certificate anymore.

#### **Permissions granting**

Next, we need to grant the new service principal access to our Key Vault. You need to use the `appId` value from the registration stage to do this.

```sh
az keyvault set-policy \
    --name signatory-keyvault \
    --spn APPID \
    --key-permissions sign list get import
```

Example:

```sh
az keyvault set-policy --name signatory --spn "d5ccc5ea-8a1f-4dc1-9673-183a4c85e280" --key-permissions sign list get import
```

#### **Enable Microsoft.ResourceHealth service (optional)**

`Microsoft.ResourceHealth` service is used to check the Key Vault availability status

```sh
az provider register --namespace "Microsoft.ResourceHealth"
```

_ATTENTION:_ The registration process can take up to an hour. To check the registration status run the command:

```sh
az provider show -n "Microsoft.ResourceHealth"
registrationState property should say Registered
```

#### **Get the subscription and tenant id for your account**

To find your subscription id, run the command:

```sh
az account list
```

Example output:

```json
[
  {
    "cloudName": "AzureCloud",
    "id": "172bb0bf-77d3-49ud-9725-a642d768tm47",
    "isDefault": true,
    "name": "My Subscription",
    "state": "Enabled",
    "tenantId": "52c46f11-1j3a-4c56-b728-1bcb03fhf48e",
    "user": {
      "name": "user@domain.com",
      "type": "user"
    }
  }
]
```

## **Backend configuration**

### **Configuration parameters**

|||||
|--- |--- |--- |--- |
|Name|Type|Required|Description|
|vault|URL|✅|Vault URL|
|tenant_id|UUID|✅|Tenant ID|
|client_id|UUID|✅|Service Principal (application) ID from the registration stage|
|client_secret|string|OPTIONAL|Used for secret based authentication. Not covered here. Not recommended.|
|client_pkcs12_certificate|string|OPTIONAL|Path to PKCS #12 file|
|client_certificate_thumbprint|string|OPTIONAL|Hex or Base64 encoded client certificate hash. Use along with client_private_key as an alternative to PKCS #12 flow|
|client_private_key|string|OPTIONAL|Path to the client private key. Use along with client_certificate_thumbprint as an alternative to PKCS #12 flow|
|subscription_id|UUID|OPTIONAL|Subscription ID. Optional. Only if Microsoft.ResourceHealth is enabled (see above)|
|resource_group|string|OPTIONAL|Resource group name. Optional. Only if Microsoft.ResourceHealth is enabled (see above)|

Example:

```yaml
vault: https://signatory.vault.azure.net/
tenant_id: 50c46f11-1d0a-4c56-b468-1bcb03a8f69e
client_id: d5ccc5ea-8a1f-4dc1-9673-183a4c85e280
client_private_key: service-principal.key
client_certificate_thumbprint: 6B7DDE60582104C37600BB337555E7517F5B834C
```

### **Environment variables**

* `AZURE_CLIENT_TENANT`
* `AZURE_CLIENT_ID`
* `AZURE_CLIENT_SECRET`
* `AZURE_CLIENT_PKCS12_CERTIFICATE`
* `AZURE_CLIENT_CERTIFICATE`
* `AZURE_CLIENT_CERTIFICATE_THUMBPRINT`
* `AZURE_CLIENT_PRIVATE_KEY`

## **Create EC-HSM key**

```sh
az keyvault key create --curve {P-256, P-256K, P-384, P-521}                                     
                       --kty {EC, EC-HSM, RSA, RSA-HSM, oct, oct-HSM}]
                       --name
                       --vault-name
```

**Example:**

```sh
az keyvault key create --curve P-256 --kty EC-HSM --name "sigy-key" --vault-name "sigy"
```

**Obtain public key hash (PKH) of above key:**

```sh
% ./signatory-cli list -c /etc/s.yaml
Public Key Hash:    tz3d6nYmR1LmSDsgJ463Kgd8EbH53pYnuv8S
Vault:              Azure
ID:                 https://sigy.vault.azure.net/keys/sigy-EC-HSM/77154e5846b4sdajbf78fs876dfse963b0b4bec
Status:             ACTIVE
Allowed Operations: [block endorsement generic]
Allowed Kinds:      [endorsement transaction]
```

**Update signatory.yaml config with PKH:**

```yaml
server:
  address: :6732
  utility_address: :9583

vaults:
  azure:
    driver: azure
    config:
      vault: https://sigy.vault.azure.net/
      tenant_id: 50a7adf11-1a9a-4b76-b468-1acdb03a8f69e
      client_id: b673iu8cc5-98c9-44ac-a688-7cafcdb9b9bcb4
      client_private_key: service-principal.key
      client_certificate_thumbprint: 643F14403B695090D8ABDC34ABBE7EF2423497352
      subscription_id: be223726da0-6dc1-4cdc-ab26-15a082bdaaa908
      resource_group: sigy

tezos:
  tz3d6nYmR1LmSDsgJ463Kgd8EbH53pYnuv8S:
    log_payloads: true
    allow:
      block:
      attestation:        # Modern terminology (was "endorsement")
      preattestation:     # Modern terminology (was "preendorsement")
      attestation_with_dal: # Required for DAL participation
      generic:
        - transaction
        - reveal
        - delegation
