# Signatory exporter

The signatory exporter allow you to take you unencrypted tezos key and export them to standard key file

You will then be allowed to import your key on different HSM using this file

For instance you can import an exported tz3 (tz3.pem) key into a yubi-hsm using those command

Note: you will need to produce a wrap key before see: https://developers.yubico.com/yubihsm-shell/yubihsm-wrap.html

```
yubihsm-wrap -a ecp256 -c sign-ecdsa -d 1,2,5 --id 100 --label MY_ECDSA_WRAPPED_KEY --in tz3.pem.pem --wrapkey wrap.key -
-out tz3.yhw

yubihsm-shell -p password -a put-wrapped --wrap-id (YOUR_WRAP_KEY_ID) --in tz3.yhw
```