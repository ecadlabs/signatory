---
id: hashicorp_vault
title: HashicorpVault
---

# Hashicorp Vault

The goal of this guide is to configure Signatory to use an Hashicorp Vault as a signing backend.

## **Vault setup**

Run Vault server or use dedicated cloud instance (HCP Vault) for secrets management

### **Install vault**

https://developer.hashicorp.com/vault/downloads

### **Run Dev Server**

```sh
docker run --cap-add=IPC_LOCK -d --name=dev-vault vault
```

### **Configure Vault Address and Token**

Set the Vault address and obtain the root token provided when starting the Vault server.

```sh
export VAULT_ADDR=http://127.0.0.1:8200
export VAULT_TOKEN={{root_token}}
```

### **Enable Transit Secrets Engine**

Enable the Transit secrets engine which is used to manage cryptographic functions.

```sh
vault secrets enable transit
```

### **Create Transit Key**

Create a new encryption key in the transit secrets engine.

```sh
vault write -f transit/keys/{{my-key}} type="ed25519"
```

### **Create Policy for Transit**

Create a policy that allows reading and writing keys in the transit engine.

```hcl
# transit-policy.hcl
path "transit/*" {
  capabilities = ["read", "create", "update", "list"]
}
```

### **Create AppRole Authentication**

Enable and configure the AppRole authentication method.

```sh
vault auth enable approle
```

### **Create AppRole Role**

Create a role for the AppRole authentication method. This role associates a set of policies with the AppRole.

```sh
vault write auth/approle/role/my-approle \
  secret_id_ttl=10m \
  token_ttl=20m \
  token_max_ttl=30m \
  token_policies="transit-policy"

```

### **Fetch Role ID and Secret ID**

Fetch the Role ID and Secret ID of the AppRole.

```sh
vault read auth/approle/role/{{my-approle}}/role-id
vault write -f auth/approle/role/{{my-approle}}/secret-id
```

## **Backend configuration**

### **Configuration parameters**

|||||
|--- |--- |--- |--- |
|Name|Type|Required|Description|
|address|URL|✅|Vault URL|
|roleID|UUID|✅|AppRole identifier|
|secretID|UUID|✅|AppRole credential|
|transitConfig.mountPoint|string|✅|Path to the transit secret engine|
|tlsCaCert|string|OPTIONAL|tlsCaCert is the path to a PEM-encoded CA cert file to use to verify the Vault server SSL certificate.|
|tlsClientCert|string|OPTIONAL|tlsClientCert is the path to the certificate for Vault communication|
|tlsClientKey|string|OPTIONAL|tlsClientKey is the path to the private key for Vault communication|


Example:

```yaml
address: "http://127.0.0.1:8200"
roleID: "5970e31e-132b-d624-f3eb-10d1fcdd3fab"
secretID: "aa9c4a24-c7f1-a278-a9db-bac58273fe7c"
transitConfig:
    mountPoint: "transit/"
```

