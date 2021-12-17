---
id: ledger_nano_s
title: Ledger Nano S
---

## Alex's Changes for Ledger Nano S:

#### Note on convention: 
Anything surrounded by curly brackets is a piece of info that will be specific to you. For example {tezos_public_key_hash} will be something on your system resembling `tz1P572ijpP...`

### Introduction to Ledger/Nano S:

They will likely describe their own products far better than we ever could. Some resources are available here
- [Ledger Website](https://www.ledger.com/)
- [Nano S Overview](https://shop.ledger.com/products/ledger-nano-s)
- [Ledger Academy](https://www.ledger.com/academy)
- [Ledger Live](https://www.ledger.com/ledger-live)

### Trade-offs of using Ledger: 
To be completed later

### Vault Setup Hints
- You CANNOT import a key to a ledger device
- Making sure that the ledger device is able to work with your linux system is enabled through udev rules. Some examples can be found [here](https://github.com/LedgerHQ/udev-rules)
  - I suggest appending the following to the section for the device you are using:
  `, ACTION=="add", GROUP="{your_user_group}"`
  - The add action is for when you plug in the device and making sure the device has the permissions group you belong to will make sure you don't need to run any commands as a root user

### Key Management
#### Setup from fresh install and recovery phrase generation
- Install ledger live, activate the developer mode (in settings -> experimental features) to get the tezos wallet/baking apps made by {whatever company makes them, fill in, possibly Zondax}
- Connect the ledger device to the machine that will be running the node/baker(s)
- Determine the ID of the ledger device
  - You must have signatory and signatory-cli set up. If this has not been done please move onto the signatory setup section and come back

  ```
  alexander@debian:~/signatory$ ./signatory-cli ledger list -c signatory.yaml
  INFO[0000] Initializing vault                            vault=ledger vault_name=ledger
  Path:           0001:0007:00
  ID:             tz1bjnGUjZFH22QSag2dyiKA5P6y24iKoTQx / b0987791
  Version:        TezBake 2.2.13```

  - The first part of the ID is important since it will be used by the signatory.yaml file to identify this ledger

- Get the public key hash from the ledger device
```
alexander@debian:~/signatory$ ./signatory-cli list -c signatory.yaml 
INFO[0000] Initializing vault                            vault=ledger vault_name=ledger
Public Key Hash:    tz1Kiak7gwhv6fvcpq9Q9ghjKNuFNYDtUJUG
Vault:              Ledger
ID:                 bip32-ed25519/44'/1729'/0'/0'
Active:             false

Public Key Hash:    tz2F7vTTMvMb2HRywjjjMpftkGDLQKoEkbsr
Vault:              Ledger
ID:                 secp256k1/44'/1729'/0'/1'
Active:             false
```
- Make sure that tezos client can access the ledger through the command `tezos-client list connected ledgers`
- Add funds to account (faucet can normally be found [here](https://teztnets.xyz/))
- Set up ledger for baking (See if you're using the bip32-25519 address you will need to use a command like `./signatory-cli ledger setup-baking bip25519/0h/0h -c signatory.yaml`). You will also need to go to the device and verufy the request to set it up for baking
```
alexander@debian:~/signatory$ ./signatory-cli ledger setup-baking bip25519/0h/0h -c signatory.yaml 
INFO[0000] Initializing vault                            vault=ledger vault_name=ledger
Authorized baking for address: tz1Kiak7gwhv6fvcpq9Q9ghjKNuFNYDtUJUG
```
- Make sure to run signatory after adding the correct info to the yaml file (`./signatory serve -c signatory.yaml` after filling in info in signatory.yaml section)
- Add the ledger device to the tezo-client as a delegate for baking (this will also require a device verification, steps found in the tezos-client setup below)

### Signatory Setup for most cases (no different setup needed for Ledger at this time)
I don't believe there is anything additional needed for signatory when using a ledger. The standard should work
- Clone [repo](https://github.com/ecadlabs/signatory)
- Make sure Go is installed (version must be greater than 1.15)
- Navigate to the cloned signatory repo
- `make signatory`
- `make signatory-cli`

#### What you need for ledger in a signatory configuration YAML file
The following is needed in a config file for signatory to know what it is looking for on a ledger nano S
```
# The vaults section is what defines the connection to the yubiHSM
vaults:
    ledger:
    driver: ledger
    config:
      # id: {First part of ledger ID you got from './signatory-cli ledger list'}
      keys:
        - "bip32-ed25519/0'/0'"
        - "secp256k1/0'/1'"
      close_after: 600800s

# This section is for public key hashes to define what is activated IRL
tezos:
  # Default policy allows "block" and "endorsement" operations
  tz3MhmeqpudUqEX8PYTbNDF3CVcnnjNQoo8N:
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

### Signatory-cli features for Ledger
Once you have signatory binaries and the ledger set up it is time to test the connection between the hardware and signatory. After completing the setup for the ledger and signatory we can test it by using the signatory-cli command `list`. Here is an example(notice the additional info from when we did it before):
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
INFO[0000] Initializing vault                            vault=ledger vault_name=ledger
Public Key Hash:    tz1fNiSGiq7X7Br1H5pgPJWJSGouBaRAw8Qb
Vault:              Ledger
ID:                 bip32-ed25519/44'/1729'/0'/0'
Active:             true
Allowed Operations: [block endorsement generic]
Allowed Kinds:      [delegation endorsement reveal transaction]
```

### Tezos Client Setup
Adding the information generated in any vault to the tezos-client is done in a single command, it is as follows:

`tezos-client import secret key {name_you_choose} http://localhost:6732/{your_public_key_hash}`

Using the same pkh as above an example command would look like:

`tezos-client import secret key {name_you_chose} http://localhost:6732/tz3c6J47hHmwuasew7Y3HMZzmy7ymDgd6cfy`

This should produce the output: `Tezos address added: tz3c6J47hHmwuasew7Y3HMZzmy7ymDgd6cfy`

Making the added PKH a delegate to begin baking/endorsing is achieved through this command (node/baker/endorser should be running already):

`tezos-client register key {name_you_chose} as delegate`

After the above command is accepted in the chain then if you navigate to a block explorer you should be able to see your account

### Final Signatory Verification Test
We can finally see that all the pieces are working together by curling the signatory service and asking for the public key associated with our active public key hash:
`curl http://localhost:6732/keys/tz3c6J47hHmwuasew7Y3HMZzmy7ymDgd6cfy`

The output can be verified by checking the public_keys file in the .tezos-client directory