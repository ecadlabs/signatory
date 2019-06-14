# Azure setup

__Rough draft, needs polish and testing__

The pre-requisites for setting up Azure KMS as a Signatory backend are;

* An active Azure subscription
* The [Azure
CLI](https://docs.microsoft.com/en-us/cli/azure/?view=azure-cli-latest) `az`
installed and configured on your computer.

## How to configure Azure.

Use the `example.yaml` signatory config file as a starting point.

You will need to create several Azure resources, and copy configuration into
the signatory config file. Let's begin.

This guide uses the `az` cli command to create all required resources.
For each command, you will get a json formatted result, or an error.

### Create a Azure resource group.

You need to specify the location you want your
Signatory to be located. This is up to you. The closer to your baker the
better, but other criteria may be important to you.

We will place our demo in the `canadaeast` location by running the command;

```sh
az group create --name signatory_resgroup --location canadaeast
```

### Create a new keyvault

Next we will create a new keyvault within our newly created resource_group by
running the command:

```sh
az keyvault create --name sigvault --resource-group signatory_resgroup --sku premium
```

The `--sku` argument must be set to premium if you want to have your keys
stored in a HSM.

From the json output from the above command, copy the following property values:

* vaultUri to the `vault_uri` prop in yaml
* name ("sigvault") to `vault` in yaml
* `tenant_id` to `directory_id` in yaml. Azure refers to tenant_id as "directory_id" when looking via the portal

### Get the subscription id for your account

To find your subscription id, run the command;

```sh
az account list
```

Copy the `id` vaule from the output into the `subscription` property in the
signatory config file. If you have multiple logins configured for your `az`
command, make sure to choose the correct one.

### Create a Service Principal for authentication

Next we need to create a "service principal" resource (also known as a "service
account"). This is the credential that allows Signatory to authenticate and work
with the Azure KMS service.

Run the command:

```sh
az ad sp create-for-rbac -n "http://signatory_serviceprincipal"
```

Copy the `name` value (http://signatory_serviceprincipal), with the `http://`
prefix into the `client_id` property under your new azure config block.
Copy the `password` value into the `client_secret` property

## Import a key to Azure

*Coming Soon*

## Generate a key in Azures HSM

You can generate a key pair within the HSM. *WARNING* This key is not
exportable, so you do not have portability. If you use this private key, you
are locked into using Azure for all signing operations. This might be good in
some aspects, such as surety, plausible deniability, etc. but your if you loose
access to your Azure account, you loose access to your key. PROCEED WITH
CAUTION. We recommend to use this approach only for testing.

```
az keyvault key create --name sigtestkey2 --vault-name sigtest2 --protection hsm --kty EC-HSM --curve P-256
```

The output from this command will show you a vaule similar to:

```
kid: https://sigtest2.vault.azure.net/keys/sigtestkey2/1757975528b04c488c36963eee6e9d5d
```

Take this value and add it to the `keys` list under your new azure
configuration block.

When you start signatory, it will connect to azure, request the public key
co-ordinates using the `kid` URL, and print the `tz` address to the console.

## Testing / Verify

To test the signing operation, you can send a post to signatory. In this
example, we are sending a operation of type `03`, which is a `generic`
operation type. We are just passing a `0` byte, which will serve the purpose of
testing that singing operations work and no more.

```sh
curl -XPOST -d '"0300"' localhost:8003/keys/tz3jbFvkPL3asPSYFnCsFeCzciqmtGB2GSXF
```

If you recieve an error from curl and on the signatory console, you will have
to investiage. If it was successful, you should see output simlar to:

```
{"signature":"p2sigR4JTRTMkT4XC4NgVuGdhZDbgaaSZpNPUserkyMCTY1GQJTFpCuihFRVk9n7YaNjA5U3cNcvJPRm7C9G5A1hsLsesVPcMu"}
```