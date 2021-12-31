---
id: yubihsm
title: YubiHSM
---
### Introduction to YubiHSM2:

They will likely describe their own products far better than we ever could. Some resources on the HSM are available here:

- [HSM website](https://www.yubico.com/products/hardware-security-module/) (make sure to check out the product brief on this page)
- [Developers Overview](https://developers.yubico.com/YubiHSM2/Product_Overview/)
- [HSM Series Support Page](https://www.yubico.com/ca/setup/yubikey-5-series/)

#### Trade-offs of using YubiHSM:
To be completed later

### Vault Setup Hints
This is the guide that was used to set up the HSM initially and gather the required tool to interface with different hosts: 
(This should get the HSM connected to your host and able to receive commands)
- [Quick Start](https://developers.yubico.com/YubiHSM2/Usage_Guides/YubiHSM_quick_start_tutorial.html)
    - You will need to complete up to and including the section titled "Adding a New Authentication Key". This will make sure your environment is set up to allow asymmetric key generation
    - One part of this is possibly defining a udev rule for allowing your user to access the yubiHSM since running things as root isn't generally advised. This [link](https://developers.yubico.com/YubiHSM2/Component_Reference/yubihsm-connector/) is helpful for setting up udev rules so your user can run the connector

### Key Management

#### Key generation on YubiHSM
- You will need to complete the section titled "Generate a Key for Signing". This will create the keys that the HSM will use for signing. A single key is generally enough to get what you need done and if you need more, they can be added in the future.

#### Importing a Secret key into the YubiHSM2 for Tezos


### Signatory Setup for most cases (no different setup needed for Yubi at this time)
I don't believe there is anything additional needed for signatory when using a YubiHSM. The standard should work:
- Clone [repo](https://github.com/ecadlabs/signatory)
- Make sure Go is installed (version must be greater than 1.12(I think))
- Navigate to the cloned signatory repo
- `make signatory`
- `make signatory-cli`

#### What you need for YubiHSM in a signatory configuration YAML file
The following is needed in a config file for signatory to know what it is looking for on a yubiHSM
```
# The vaults section is what defines the connection to the yubiHSM
vaults:
# Name is used to identify backend
  yubi:
    driver: yubihsm
    config:
      address: localhost:12345 # Address for the yubihsm-connector
      password: {password_you_set_when_creating_authentication_key}
      auth_key_id: 1 # This is the ID of the authentication key you created for the YubiHSM

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

### Signatory-cli features for YubiHSM
Once you have signatory binaries and the YubiHSM set up it is time to test the connection between the hardware and signatory. After completing the setup for the HSM and signatory we can test it by using the signatory-cli command `list`. Here is an example:
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
INFO[0000] Initializing vault                            vault=yubihsm vault_name=yubi
Public Key Hash:    tz1RKhyJmze24D3EerrGpCZG6P572ijpPUc3
Vault:              YubiHSM
ID:                 bf5d
Active:             true
Allowed Operations: [block endorsement generic]
Allowed Kinds:      []
```

### Final Signatory Verification Test
We can finally see that all the pieces are working together by curling the signatory service and asking for the public key associated with our active public key hash:
`curl http://localhost:6732/keys/{your_public_key_hash}`

The output can be verified by checking the public_keys file in the .tezos-client directory