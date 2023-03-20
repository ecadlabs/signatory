---
id: architecture
title: Signatory Architecture
sidebar_label: Signatory Architecture
---

# Signatory C4 Architecture Model 

Signatory is the perfect solution for secure and reliable remote signing in Tezos Blockchain cases. With easy-to-use configuration options, users can set up vaults and policies to ensure that only authorized operations are signed. Signatory also supports a variety of hardware-based and cloud-based HSMs, such as [AWS KMS](https://aws.amazon.com/kms/) and [YubiHSM](https://www.yubico.com/?utm_source=google&utm_medium=pd:search&utm_campaign=US_B2C_LeadGen_Google_SEM_Brand&utm_content=&gclid=CjwKCAiAmJGgBhAZEiwA1JZolnAOjpSi_GVY8qz7NyLHASwkXHBu2t1aPNWl2WWHl4Nb2S19OsAWMBoCGucQAvD_BwE), to protect cryptographic keys.

Using Signatory, users can securely store their secret keys and control which operations can be signed, reducing the risk of losing or having their keys stolen. Signatory also allows users to sign transactions on hardware not connected to the internet, providing an additional layer of security.

[C4 architecture diagrams](https://c4model.com/) are visual modelling languages used to communicate software system architectures. They are designed to be simple, easy to understand and provide a high-level view of a system's components and how they interact. C4 diagrams are typically organized into a hierarchy of increasing detail, with each view building on the previous one.

[Domain-driven design](https://martinfowler.com/tags/domain%20driven%20design.html) ([DDD](https://learn.microsoft.com/en-us/archive/msdn-magazine/2009/february/best-practice-an-introduction-to-domain-driven-design)) is a software development approach emphasizing the importance of understanding the business domain to create effective software solutions. C4 diagrams can help developers understand the domain of the system they are building and design software that aligns with the domain concepts and principles. By using C4 diagrams to visualize the system's architecture, developers can better understand how the system fits into the larger business context and how the different components of the system interact with one another.

The C4 system architectural model is a set of diagrams used to represent the architecture of a software system. There are four levels in the C4 model, each providing an increasing level of detail about the software system.

1. System Context Diagram: This is the highest level of the C4 model and provides a high-level view of the software system and its environment. It shows the system as a box in the center, surrounded by its users and other systems it interacts with. The diagram also shows the relationships between the system and its environment, such as data flow and requests.
2. Container Diagram: The container diagram shows the software system as a set of containers, each containing its own set of components. It shows how the different containers interact with each other to form a larger system. This level of the C4 model provides more detail about the software system's components and their interactions.
3. Component Diagram: The component diagram provides a more detailed view of the software system's components and their interaction. It shows the internal structure of each container and the relationships between the components. This level of the C4 model provides a detailed view of the software system's components and their interactions.
4. Code Diagram: This is the lowest level of the C4 model, and it provides a detailed view of the code structure of each component. It shows the classes, functions, and other code artifacts that make up each component.

There is no requirement to detail every container and component. Often the high-level description is enough to convey the required understanding. It is also unnecessary to detail the code level, as a sufficiently detailed component diagram can suffice.

### 1. Signatory System Context


For Signatory, a remote signer application for the Tezos blockchain, the C4 system context diagram shows the Signatory software system as the central box. The diagram includes the Signatory user, responsible for setting up the system's configuration, and the client software system, which submits requests to the Tezos API. The diagram also shows various vaults, such as AWS KMS and YubiHSM, which Signatory uses to store cryptographic keys, and the Prometheus service, which stores and tracks metrics data.
```mermaid
flowchart TD
User["Signatory User Setup
[CONFIG]
Bakers or Institutions looking\n to enforce signing policies"]

S["Signatory
[Software System]
Provides signing options for\n cloud-based or hardware-based HSMs"]

User-- "Defines Vault and Policy" -->S

OC["Client
[Software System]
submits requests to Tezos API"]

V["Vaults
[Software Systems]
 AWS KMS, Azure Key Vault, GCP Key Management,\n YubiHSM, local private key"]

PS["Prometheus Service
[Software System]
Provides an API to store and track metrics"]

S-- "Listens for operations" -->OC
S-- "Remote Signer for" -->V
S-- "Exposes metric data to" -->PS

classDef focusSystem fill:#1168bd,stroke:#0b4884,color:#ffffff
classDef supportingSystem fill:#666,stroke:#0b4884,color:#ffffff
classDef person fill:#08427b,stroke:#052e56,color:#ffffff
class User person
class S focusSystem
class OC,V,PS supportingSystem

```
### 2. Signatory Container Model
The Signatory container model is a C4 architecture diagram showing the different elements of the Signatory system. The diagram shows the Signatory software system as the central container, with various supporting software systems surrounding it. These supporting systems include client software for submitting requests to the Tezos API, the Prometheus service for storing metrics data, and various hardware-based and cloud-based HSMs for protecting cryptographic keys. The diagram also shows Signatory's different vaults to store cryptographic keys, such as AWS KMS and YubiHSM. 
```mermaid
flowchart TD
User["Signatory User
[Person]
Baker or Institution operation requests with key security"]

CFG["Configuration File
[File]
select vault, keys and policy"]

OC["Client
[Software System]
submits requests to Tezos API"]

P["Software Application
[PROMETHEUS]
Record and store metrics data"]

SL["HTTP Service 
[SIGNING LISTENER]
captures operation signing requests"]

ML["HTTP Service 
[METRICS LISTENER]
captures metric data"]

SIG["Service 
[SIGNATORY SERVICE]
check policy and sign"]

Y["Hardware Security Module
[YUBIHSM]
protect cryptographic keys"]

L["Hardware Wallet
[LEDGER]
stores user's private keys"]

LS["File
[LOCAL-SECRET]
stores user's private keys on disk"]

AWS["Cloud Service 
[AWS]
blockchain infrastructure"]

G["Cloud Service
[GOOGLECLOUD]
blockchain infrastructure"]

A["Cloud Service
[AZURE]
blockchain infrastructure"]


User-- "Get Post <br>[HTTP]"-->OC
User-- "configures<br>[FILE]"-->CFG
OC-- "Get Post <br>[HTTP]"-->SL
ML-- "Get<br>[HTTP]" -->P

subgraph Signatory[Signatory]
SIG--"exposes metrics to<br>[JSON]" -->ML
CFG-- "governs<br>[CODE]"-->SIG
SL-- "informs<br>[CODE]" -->SIG
end

SIG-- "sign<br>[USB]" --->L
SIG-- "sign<br>[JSON]" --->LS
SIG-- "sign<br>[USB]" --->Y

subgraph Cloud[Cloud]
SIG-- "sign<br>[HTTP]" ---> AWS
SIG-- "sign<br>[HTTP]" ---> G
SIG-- "sign<br>[HTTP]" ---> A
end


classDef container fill:#1168bd,stroke:#0b4884,color:#ffffff
classDef person fill:#08427b,stroke:#052e56,color:#ffffff
classDef supportingSystem fill:#666,stroke:#0b4884,color:#ffffff
classDef cloud fill:#089319,stroke:#089319,color:#ffffff
class User person
class SIG,POL,SL,ML,CFG container
class C cloud
class P,AWS,G,A,L,LS,Y,T,OC supportingSystem
```
### 3. Signatory Component Model 
A sequence diagram is a way to express the behaviour of the underlying code in a software system. It shows the interactions between different system components over time, highlighting how the system behaves and responds to different inputs. Using a sequence diagram, developers can better understand the flow of data and control within the system and identify potential issues or areas for improvement.

The sequence diagram for the Signatory remote signer application shows the behaviour of the underlying code in the system. It highlights how the different components of the system interact with one another over time, showing the flow of data and control within the system. Using a sequence diagram, developers can better understand how the system behaves and identify potential issues or areas for improvement.
```mermaid
sequenceDiagram
autonumber
actor Client
participant Signatory
participant Signature service
participant Metrics server
participant Vault

Signatory->>+Signatory: RootCmd
Signatory->>+Signatory: read config
Signatory->>+Signatory: Register Vaults (Yubikey/Azure/CloudKMS)
Signatory->>+Signatory: Initialize Vault (Yubikey/Azure/CloudKMS)
Signatory->>+Signatory: ServeCmd

Signatory->>+Signature service: Start service
Signatory->>+Metrics server: Start service


Client->>+Signature service: GET /authorized_keys 
Signature service->>+Client: Send Authorized keys (Authorised list of clients)
loop
Client->>+Signature service: Check the list of configured keys 
end
alt If Found
Client->>Signature service: POST /keys/<account> (Signing key)
Client->>Signature service: Digest string + payload
Signature service-->>+Client:Show authorized key not found error
else Else
Client-->>+Signature service : continue loop
end

alt If signing-key found in key-cache
Signature service->>+Signature service: Return key from cache
else Else
Signature service->>+Vault: GET /public-key
Vault->>+Signature service : Send public key (PEM format)
Signature service->>+Signature service: Encode secret key into PKH(Public Key Hash)
Signature service->>+Vault: Request signing operation
end

Vault->>+Signature service : Send Error or Signature
Signature service->>+Client: Send Error or Signature
```

### 4. Tezos Signing Component Model

Tezos uses elliptic curve cryptography to manage private/public key addresses, sign data, and check signatures. Signing a transaction involves hashing the operation request, prefixing it with a watermark, and then signing the resulting byte string with the user's secret key. The signature is then appended to the operation request to create a signed transaction, which can be broadcast to the network for confirmation.

```mermaid
flowchart TB
TJ["Transfer operation
[JSON]
Transaction from Alice to Bob<br>./octez-client -l transfer 1 from alice to bob --burn-cap 0.06425"]
TN["Tezos Node
[Infrastructure]
hosts RPC service"]
FT{First<br>Transaction?}
Reveal["Reveal operation
[Bytes]
Declare Public Key "]
TB["Transaction in Binary
[Bytes]
a transfer operation request"]
W["Magic Byte 
[Bytes]
prefix the request with 0x03"]
B["Blake2b Hash
[Bytes]
hash the operation request"]
ED["Ed25519 Sign
[Bytes]
sign the operation request"]
SK["Secret Key
[Bytes]
alice_sk.hex"]
SIGNATORY["Signatory Signing Listener
[HTTP Service]
captures operation signing requests"]
ST["Signed Transaction
[Bytes]
signed hashed prefixed operation
signature.hex"]
TJ --> FT
FT -- "No<br>operation.kind=transaction<br>Forge RPC" --> TN 
FT -- "Yes" --> Reveal 
Reveal -- "operation.kind=reveal<br>Forge RPC" --> FT
TN-- "Serialize" -->TB
TB-- "Add" -->W
W-- "Hash" -->B
B-- "Send operation.hex" -->ED
SK-- "from vault" -->SIGNATORY
SIGNATORY-- "Send alice_sk.hex" -->ED
ED--"Hash " -->ST
ST-- "Injection RPC<br>
../injection/operation?chain=main<br> --data $(cat operation.hex)$(cat signature.hex)" -->TN
classDef node fill:#0C36F1,stroke:#0b4884,color:#ffffff
classDef key fill:#F41F38,stroke:#0b4884,color:#ffffff
classDef transaction fill:#2591BE,stroke:#0b4884,color:#ffffff
classDef signature fill:#F1A40C,stroke:#0b4884,color:#000000
class FT,Reveal,TJ,TB,W,B transaction
class TN node
class SK key
class ED,SIG,ST signature
```
Diagram adapted from [An Introduction to Tezos RPCs: Signing Operations](https://ocamlpro.com/blog/2018_11_21_an_introduction_to_tezos_rpcs_signing_operations/)

### Simplified Signing Model
This Mermaid sequence diagram is a simplified depiction of signing a transaction on the Tezos blockchain.

- The transaction is first forged using the Tezos RPC.
- The resulting operation hexadecimal is then sent to a remote signer for signing.
- The remote signer receives the operation and the secret key corresponding to the sender's address (in this case, Alice's).
- The remote signer signs the transaction and returns the resulting signature hexadecimal.
- The signed transaction is then sent back to the Tezos RPC for injection into the blockchain. 
```mermaid
sequenceDiagram
    actor U as User
    participant OC as Octez Client
    participant TR as Tezos RPC
    participant RS as Remote Signer
    participant V as Vault
    U->>OC: 
    Note over U, OC : octez-client -l transfer 1 from<br>alice to bob 
    OC->>TR: Serialized
        Note over OC,TR: 0b6b28b6285d1a7146c17dd85f<br>b54b7dc7f68bd7b9a49569ac8f<br>9d6150baa2946c00172d6807f4<br>977e1c67252bdfabbfb37875e3<br>1d4f009dbb0180bd3fe0d403c0<br>843d00001be972fc31a358a26c<br>e970e921e357d95d5abe2400<br>
    TR->>TR: Add Magic Byte
            Note over TR: 030b6b28b6285d1a7146c17dd85f<br>b54b7dc7f68bd7b9a49569ac8f<br>9d6150baa2946c00172d6807f4<br>977e1c67252bdfabbfb37875e3<br>1d4f009dbb0180bd3fe0d403c0<br>843d00001be972fc31a358a26c<br>e970e921e357d95d5abe2400<br>
    TR->>TR: Blake58 Hash
    V->>RS : alice.hex
    Note over V, RS: bab4df908ea857e3abecc4<br>0a49e84b4fdc47121b73af<br>461398fc133715199569
    RS->>RS: signature.hex
    Note over RS: b965f666f400c1889915a0c6f1a1092cd96c0814d1b<br>bb765678fcf2c86c5079ae1f3735878f8717c230859<br>85c7aa9536fcc9228f42c5d4b6160c2b52a010970b
    TR->>RS: operation.hex
RS->>TR: Send to RPC for Injection
    Note over RS,TR :  'http://127.0.0.1:8732/injection/<br>operation?chain=main' --data '"'$(<br>cat operation.hex)$(cat signature.hex)'"'
    
```
