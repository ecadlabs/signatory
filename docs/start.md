---
id: start
title: Getting Started
sidebar_label: Getting Started
---


## What is Signatory

Signatory is a remote signing daemon. Signatory can be used by Tezos Bakers to add additional security to their systems. Signatory can also be used by applications that require signatures but do not want to have the responsibility of storing secret keys.

Signatory currently supports [YubiHSM][yubi], [Azure Key Vault][azure], and for development/prototyping purposes, Signatory can sign with a local private key.

The goal of the Signatory service is to make key management as secure as possible in a Cloud and on-premise HSM context.

Security and convenience are often opposed, but we hope to make it easier for the community to manage their keys in an adequately secure manner.

By supporting multiple Cloud KMS/HSM systems, we hope to help the network from centralization on a particular Cloud offering. In the first year of the Tezos network operation, there was anecdotal evidence that many bakers run on AWS. AWS is a superb provider, but concentrating nodes on one cloud vendor centralizes the network’s underlying infrastructure, which is not desirable.

Observability is a first-class concern. Signatory allows for rich reporting and alerting capabilities. It exposes metrics about its operation via Prometheus metrics, enabling teams to set up robust monitoring of their critical infrastructure and allowing operators to see historical trends, signing volumes, errors and latencies. Users can report feature requests, security issues, or bug reports can via the Github project page: 
github.com/ecadlabs/signatory or via email to security@ecadlabs.com

Security issues can be encrypted using the keys available at keybase/jevonearth

[yubi]: https://www.yubico.com/products/hardware-security-module/
[azure]: https://docs.microsoft.com/en-us/azure/key-vault/

## Following this guide

:::note Conventions
Text surrounded by curly brackets is a piece of info that will be specific to you. For example, the reader should replace `{tezos_public_key_hash}` with your Tezos Address (Public Key Hash) which starts with either `tz1`, `tz2`, or `tz3`, and looks like `tz1Ke2h7sDdakHJQh8WX4Z372du1KChsksyU`.
:::

### Signatory Setup for most cases
I don't believe there is anything additional needed for signatory when using a YubiHSM. The standard should work
- Clone [repo](https://github.com/ecadlabs/signatory)
- Make sure Go is installed (version must be greater than 1.15), link [here](https://go.dev/doc/install)
- Navigate to the cloned signatory repo
- `make signatory`
- `make signatory-cli`

## Signatory Configuration
Signatory reads a YAML configuration file to determine how it should behave and what different accounts can do. There are 3 main section to the signatory configuration YAML file. They are:
- The server section
- The vaults section
- The tezos/account section

#### The Server Section:
The server section defines the ports that signatory will exposes for different purposes. The following is an example of what the server section can look like:
```
server:
  # Address/Port that Signatory listens on
  address: :6732
  # Address/Port that Signatory serves prometheus metrics on
  utility_address: :9583
```

#### The Vaults Section:
The vaults section defines which backend signatory will use that has the secret key used for signing. The general structure of this section will be as follows:
```
vaults:
# Name is used to identify backend during import process
  {backend_keyword}:
    driver: {driver_keyword}
    config:
      {various_configuration_options}
```

For each individual backend their specific page will have greater detail about what is needed in terms of configuration. The overall status of different backend support can be found [here](https://github.com/ecadlabs/signatory#backend-kmshsm-support-status)

#### The Tezos/Account Section:
The tezos/account section defines what actions a backend can do within signatory. The overall structure is as follows and can be repeated for as many accounts as you have/need:
```
tezos:
  # Comments to explain your choices/decisions
  {pkh_of_the_account_associated_with_the_backend}: 
    log_payloads: {true | false}
    allowed_operations:
    # List of [generic, block, endorsement]
    - {your_choices_for_operations}
    allowed_kinds:
    # List of [endorsement, ballot, reveal, transaction, origination, delegation, seed_nonce_revelation, activate_account]
    - {your_choices_for_kinds}
    authorized_keys:
    # Allow sign operation only for clients specified below. Same syntax as `server/authorized_key`
      - *authorized_key
```

Descriptions of the above options:

Logging:
- log_payloads: 

Allowed Operations:
- generic: 
- block: 
- endorsement: 

Allowed Kinds:
- endorsement: 
- ballot: 
- reveal: 
- transaction:
- origination:
- delegation:
- seed_nonce_revelation:
- activate_account:

Authorized Keys: Client specific operations, someone with more knowledge than me please fill this in

## Tezos Client Setup for Signatory
Adding the information generated in any vault to the tezos-client is done in a single command, it is as follows:

`tezos-client import secret key {name_you_choose} http://localhost:{server_address}/{your_public_key_hash}`

Using an example server_Address/pkh an example command would look like:

`tezos-client import secret key {name_you_chose} http://localhost:6732/tz3WxgnteyTpM5YzJSTFFtnNYB8Du31gf3bQ`

This should produce the output: `Tezos address added: tz3WxgnteyTpM5YzJSTFFtnNYB8Du31gf3bQ`

Making the added PKH a delegate to begin baking/endorsing is achieved through this command (node/baker/endorser should be running already):

`tezos-client register key {name_you_chose} as delegate`

After the above command is accepted in the chain then if you navigate to a block explorer you should be able to see your account as a delegate