# YubiHSM 2

## YubiHSM 2 setup

The goal of this guide is to configure Signatory to use a Yubi HSM 2 as a signing backend. We will also show how to generate a new key inside the YubiHSM 2 and use it with signatory.

To setup Yubi HSM 2 as a signing backend for Signatory, you will need:

* A Yubi HSM 2 device
* A machine with the Yubi SDK installed on it https://developers.yubico.com/YubiHSM2/Releases

See [YubiHSM 2: Practical Guide](https://developers.yubico.com/YubiHSM2/Usage_Guides/YubiHSM_quick_start_tutorial.html)

### Start the connector

```sh
yubihsm-connector -d
```

You can verify that everything is working by visiting http://127.0.0.1:12345/connector/status with a browser

### Start `yubihsm-shell` using

```sh
yubihsm-shell
```

### Connect to YubiHSM 2

```sh
yubihsm> connect
```

### Create a new authentication yey

YubiHSM 2 comes with a pre-installed authentication key `1` and a key derivation password `password`

```
yubihsm> put authkey 0 2 yubico 1 generate-asymmetric-key,put-asymmetric-key,delete-asymmetric-key,put-wrap-key,export-wrapped,import-wrapped,sign-ecdsa,sign-eddsa sign-ecdsa,sign-eddsa,exportable-under-wrap,export-wrapped,import-wrapped password
```

## Backend configuration

### Configuration parameters

Name | Type | Required | Description
-----|------|:--------:|------------
address | host:port | ✅ | Connector address
password | string | ✅ | Auth key derivation password 
auth_key_id | uint16 | ✅ | Auth key Object ID
key_import_domains | uint16 | | Domains mask for newly imported keys. Default value is 1

Example:

```yaml
address: localhost:12345
password: password
auth_key_id: 2
```

### Environment variables

* `YUBIHSM_CONNECT_ADDRESS`
* `YUBIHSM_PASSWORD`
* `YUBIHSM_AUTH_KEY_ID`
* `YUBIHSM_KEY_IMPORT_DOMAINS`

## Import options

Name | Type | Description
-----|------|------------
name | string | New key name (label). Otherwise will be auto generated.
domains | uint16 | Domains mask to be assigned to the newly imported key. `key_import_domains` parameter value will be used by default.