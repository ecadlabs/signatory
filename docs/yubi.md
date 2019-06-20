# Yubi HSM 2 setup

__Rough draft, needs polish and testing__

The goal of this guide is to configure Signatory to use a Yubi HSM 2 as a
singing backend. We will also show how to generate a new key inside the Yubi
HSM and use it with signatory.

To setup Yubi HSM 2 as a signing backend for Signatory, you will need:

* A Yubi HSM 2 device
* A machine with the Yubi SDK installed on it https://developers.yubico.com/YubiHSM2/Releases

## Create a Key in your Yubi HSM

On your machine which as the Yubi HSM run the following command

```sh
yubihsm-connector -d
```

You can verify that everything is working by visiting http://127.0.0.1:12345/connector/status with a browser

Now we will use the yubihsm-shell to create a tz2 key inside the HSM

Start yubihsm-shell using

```sh
yubihsm-shell
```

Connect to the yubihsm connect using
```sh
yubihsm> connect
```

Open a session using the default password (`password`)

```sh
session open 1 password
```

Generate a key inside the Yubi HSM

tz1:
```sh
generate asymmetric 1 400 my_tz1_key 1,2,3 exportable-under-wrap,sign-eddsa ed25519
```

tz2:
```sh
generate asymmetric 1 400 my_tz2_key 1,2,3 exportable-under-wrap,sign-ecdsa eck256
```

tz3:
```sh
generate asymmetric 1 400 my_tz3_key 1,2,3 exportable-under-wrap,sign-ecdsa ecp256
```


## Connecting to Yubi HSM from Signatory

```yaml
yubi:
  - host: localhost:12345
    password: password
    auth_key_id: 1
```

Start signatory it will list all the keys that it detects on the Yubi HSM

You should see something similar to:

```
INFO[0000] Discovering supported keys from vault(s)...  
INFO[0001] Keys discovered in Key Vault:
               
INFO[0001] tz2Ch1abG7FNiibmV26Uzgdsnfni9XGrk5wD (Found in vault, not configured for use in signatory.yaml) 
```

You must copy your tz2 key into the `tezos.keys`
list for Signatory to carry out signing operations using this address.


## Testing / Verify

To test the signing operation, you can send a post to signatory. In this
example, we are sending a dummy operation of type `02`, which is a `endorsement`
operation type. 

```sh
curl -XPOST \
    -d '"02111111111111111111"' \
    localhost:8003/keys/tz3Tm6UTWmPAZJaNSPAQNiMiyFSHnRXrkcHj
```

If you receive an error from curl and on the signatory console, you will have
to investigate. If it was successful, you should see output similar to:

```
{"signature":"p2sigR4JTRTMkT4XC4NgVuGdhZDbgaaSZpNPUserkyMCTY1GQJTFpCuihFRVk9n7YaNjA5U3cNcvJPRm7C9G5A1hsLsesVPcMu"}
```