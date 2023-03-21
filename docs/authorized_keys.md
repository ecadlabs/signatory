---
id: authorized_keys
title: Authorized_Keys Configuration
---
# Signatory's Authorized Key Authentication Feature

Signatory's remote policy service feature allows custom policy schemes beyond simple request and operation lookup to be implemented externally. This feature is authenticated using a signature, which requires the public key to be added to the authorized_keys list.

## Authentication

Authentication is the process of verifying the identity of a user or system. In the context of cryptographic keys, authentication ensures that the keys are legitimate and belong to the authorized parties.

The authorized key authentication feature in Signatory allows the server to verify that the response from the policy service is authentic. This is done by checking the signature of the payload against the authorized public keys in the authorized_keys list.

## When to Use the Feature

The authorized key authentication feature should be used when there is a need to protect the system from unauthorized access or tampering. For example, if keys are provided by a third party or created on a different system, the feature can ensure that only legitimate keys are imported into the system.

## Importance of Naming Keys

Naming keys is important as it helps to identify the key and its purpose. This is especially important in large organizations where there may be many keys in use. Giving the key a descriptive name will make it easier to locate and manage in the future. This will also prevent operators from accidentally deleting keys during housekeeping tasks.

## Testing the Feature

To test the authorized key authentication feature, you can use the reference implementation provided by Signatory. The reference implementation is the approve list service, which allows authorized keys to be added or removed from the list.

To test the feature, you can perform the following steps:

1. Add a public key to the authorized_keys list using the approve list service.
2. Send a request to the policy service with a payload signed using the authorized key.
3. Verify that the response from the policy service is authenticated using the authorized public key.

By following these steps, you can ensure that the authorized key authentication feature is working as intended and that only legitimate keys are being used to access the system.