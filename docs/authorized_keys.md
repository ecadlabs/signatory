---
id: authorized_keys
title: Authorized_Keys Configuration
---
# Signatory's Authorized Key Authentication Feature

Signatory provides the option to authenticate the octez-client, by specifying an "authorized key" in the Signatory configuration file.  

## Motivation

An authorized key can be configured to ensure that Signatory only signs requests from an octez-client instance containing the private key.

## Configuration

First, a key pair is generated using octez-client:

```bash
octez-client gen keys signatory-auth
```

Next, find the public key value:

```bash
cat ~/.tezos-client/public_keys | grep -C 3 signatory-auth
```

Finally, add the public key value to the Signatory configuration file.  It belongs within the `server` declaration:

```yaml
server:
  address: :6732
  utility_address: :9583
  authorized_keys:
    - edpkujLb5ZCZ2gprnRzE9aVHKZfx9A8EtWu2xxkwYSjBUJbesJ9rWE
```

Restarting the Signatory service is required to apply the configuration change.  Henceforth, the Signatory service will only accept requests from the octez-client that is using the private key associated with the public key specified in the configuration file.
