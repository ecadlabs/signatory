---
id: debugging
title: Tips and tricks for debugging & testing
---

This document provides some tips & utilities for Signatory developers.



## Octez tezos-signer

The Octez tezos-signer is the signer of reference for Tezos. Signatory and tezos-signer implement the same core signing capabilities. Running `tezos-signer` for comparative purposes can be helpful when testing or developing signatory. 

## Getting tezos-signer

Download the latest `tezos-signer` binary from the _Releases_ page at https://github.com/serokell/tezos-packaging
You will also want the `tezos-client` binary for testing & verification purposes.

## Setup tezos-signer with a local secret

To genereate a new secret using `tezos-signer` run the command:

```
tezos-signer gen keys octez_signer_key
```

This will create (or add to) the configuration files in `~/.tezos-signer`

:::tip
You can use many of the familiar `tezos-client` sub-commands with the `tezos-signer` such as;

`tezos-signer list known addresses` and `tezos-signer show address octez_signer_key`
::: 

Start the `tezos-client` in `http` listner mode, with no authentication.

```
tezos-signer launch http signer
```

With this secret in place, you can now add this new remote signer to your `tezos-client` configuration by running the command. (Don't forget to replace PKH with the public key hash of your newly generated key in the previous steps)

```
tezos-client import secret key octez_signer_remote_key http://localhost:6732/${PKH}
```

You can now test that this key is working for signing purposes by using the `tezos-client sign` command. This command will send the value `0x00` from `tezos-client` to the remote signer. Adding the `--log-requests` flag is helpful for debugging.

```
tezos-client sign bytes 0x00 for octez_signer_local_key
```

## Setup tezos-signer with a ledger device

Ledger devices have two applications for Tezos, an interactive "Tezos Wallet" app, and a "Tezo Baking" app which is designed for unattended use when operating a Tezos baker on the Tezos network.


### Tezos Baking App

Before you begin, make sure you have the "Tezos Baking" app installed on your device. The Tezos Baking app is available via the Ledger Live application. To be able ti install "Tezos Baking" you must enable the "Developer Mode" option in Ledger Live settings.

When you have installed the Tezos Baking app on your ledger, make sure the Ledger device is connected to your computer, powered on, ant the "Tezos Baking" app is running.

```
$ tezos-signer list connected ledgers
## Ledger `stiff-sloth-grown-grouse`
Found a Tezos Baking 2.3.2 (git-description: "") application running on
Ledger Nano S at [0003:0051:00].

To use keys at BIP32 path m/44'/1729'/0'/0' (default Tezos key path), use one
of:
  tezos-client import secret key ledger_jev "ledger://stiff-sloth-grown-grouse/bip25519/0h/0h"
  tezos-client import secret key ledger_jev "ledger://stiff-sloth-grown-grouse/ed25519/0h/0h"
  tezos-client import secret key ledger_jev "ledger://stiff-sloth-grown-grouse/secp256k1/0h/0h"
  tezos-client import secret key ledger_jev "ledger://stiff-sloth-grown-grouse/P-256/0h/0h"
```
:::caution
Note that we ran the `tezos-signer` command, but the output lists command examples using the `tezos-client` command. Beware to double check if you are copying/pasting this command!

The `ledger_jev` alias will likely look different on your system. Please adjust the commands accrodingly.
:::

The "Animal mnemonic" scheme is a way of identifying your ledger by the secret on the device. If you change the root secret on your device, you will get a different animal mnemonic.

We will configure `tezos-signer` with the ed25519 secret. Run the following command (_NOTE!: We are running the `tezos-signer` command!)

```
tezos-signer import secret key ledger_jev "ledger://stiff-sloth-grown-grouse/ed25519/0h/0h"
```

If you plan to bake with this ledger, you need to setup the ledger device to allow it to bake. When you run the setup command, you will be prompted by the Ledger device to Review the Request, and approve it.

```
$ tezos-signer setup ledger to bake for "ledger://stiff-sloth-grown-grouse/ed25519/0h/0h"
Setting up the ledger:
* Main chain ID: 'Unspecified' -> NetXLH1uAxK7CCh
* Main chain High Watermark: 0 -> 0
* Test chain High Watermark: 0 -> 0
Authorized baking for address: tz1M3kiQUMPcTseo72i1twdiV4iTY5yiGNSz
Corresponding full public key: edpkuNyLH57vRp2dyzeDSg2G7AarZcp29DQnkQaXrSNdkRkAE4B1ZA
```

Testing signatures. 

Here are some sample baking operations that can be used to test. These operations are taken from a Ithaca chain. 

```bash title="Signing an example Endorsement for testing purposes (Magic byte 0x13)"
$ tezos-client sign bytes 0x137a06a7703e47ad79416e7bdceb65156abdbcfd4b1237caf488cbfc39d88c836840bf0bc81509b9002513b8000000008c41b04d3a8648732fb22507447214aa698a235862f30b956e36a37a7d36eb7c for octez_signer_remote_ledger
Signature: edsigu66k8pYbKvhRbQizVL41XApHz9y6FSj4E6CowvWUsD13j7BDQJAJMh3id4LFhqsip6AhnpcYhRmvMyV4enAnyvEHbTiVZZ
```

```bash title="Signing an example Pre-Endorsement for testing purposes (Magic byte 0x12)"
$ tezos-client sign bytes 0x127a06a7703e47ad79416e7bdceb65156abdbcfd4b1237caf488cbfc39d88c836840bf0bc81409b9002513b8000000008c41b04d3a8648732fb22507447214aa698a235862f30b956e36a37a7d36eb7c for octez_signer_remote_ledger
Signature: edsigtaMbMAePuHrEi6cHAc8qKJjrdF9LWdewBJrmrYZTKWAyV1JYADySGovoqkuvwY68UwBxxyj3MJ2Ft7pNAKhbhc6gP4VP8p
```

```bash title="Signing an example block for testing purposes (Magic byte 0x11)"
tezos-client sign bytes 0x117a06a770002397ee0c68e4ef4a35e2f768012c2f3b560bb80eb8849327696b6843e20842ca5e01345f000000006270c6650469204194e88ec93cdc7ee5d0aa42908ad49e4e0fb7242d406e73d3a48528d4af00000021000000010200000004002397ee0000000000000004ffffffff000000040000000076222f1388f0a7d6b53b96fde78a2b79b50a19282c48eb003cbdffb6b3669e3897440e9db3d73900616e3f720e162588071444071312d967a7d38f7ea23a480c0000000061fed54022b203000000 for octez_signer_remote_ledger
```


The ledger device will prompt you to confirm sharing the public key, and after that, `tezos-signer` will add a new entry to its configuration files in ~/.tezos-signer`

#### configure tezos-client to use tezos-signer

```bash title="tezos-client creating a new account using a remote signer service"
tezos-client import secret key octez_signer_remote_ledger http://localhost:6732/tz1M3kiQUMPcTseo72i1twdiV4iTY5yiGNSz
Tezos address added: tz1M3kiQUMPcTseo72i1twdiV4iTY5yiGNSz
```
:::info
`tezos-client` has a quirk where we pass the URI http://localhost:6732/tz1M3kiQUMPcTseo72i1twdiV4iTY5yiGNSz to the command, but if you do a curl on that URL, the `tezos-signer` will return a 404. The `tezos-client` rewrites the URL to include the `/keys/` slug. If you want to get the public key for a PKH from the remote signer, you can use curl like this: 

```bash title="fetching public key from remote signer using curl"
curl -v http://localhost:6732/keys/tz1M3kiQUMPcTseo72i1twdiV4iTY5yiGNSz
{"public_key":"edpkuNyLH57vRp2dyzeDSg2G7AarZcp29DQnkQaXrSNdkRkAE4B1ZA"}
```
:::
