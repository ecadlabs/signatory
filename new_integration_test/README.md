## Signatory Integration Test
Folder Organization:

- **cli/**: Tests for the signatory CLI commands (list, help, version, etc.)
- **server/**: Tests for server-side functionality like authorized keys
- **metrics/**: Tests for monitoring and metrics collection
- **vaults/**: Tests for different vault implementations (currently empty)
- **operations/**: Tests for actual Tezos operations and transaction types (currently empty)

### Test Keys Used in Integration

- alice
    - pkh: tz1VSUr8wwNhLAzempoch5d6hLRiTh8Cjcjb
    - pk: edpkvGfYw3LyB1UcCahKQk4rF2tvbMUk8GFiTuMjL75uGXrpvKXhjn
    - sk: unencrypted:edsk3QoqBuvdamxouPhin7swCvkQNgq4jP5KZPbwWNnwdZpSpJiEbq (from signatory)

- bob
    - pkh: tz1aSkwEot3L2kmUvcoxzjMomb9mvBNuzFK6
    - pk: edpkurPsQ8eUApnLUJ9ZPDvu98E8VNj4KtJa1aZr16Cr5ow5VHKnz4
    - sk: unencrypted:edsk3RFfvaFaxbHx8BMtEW1rKQcPtDML3LXjNqMNLCzC3wLC1bWbAt (from signatory)

- opstest
    - pkh: tz1RKGhRF4TZNCXEfwyqZshGsVfrZeVU446B
    - pk: edpkvSkEEfVMKvAv87env4kMNwLfuLYe7y7wXqgfvrwJwhJJpmL1GB
    - sk: unencrypted:edsk4ZuzTnZUqetnF7icqpjQ3RT9GPJQ8HAHTRHZhKQQjWmeneQJ7C (from signatory)

- opstest1
    - pkh: tz1R8HJMzVdZ9RqLCknxeq9w5rSbiqJ41szi
    - pk: edpktfLxRbpLeFjL49Rz2xtBwPaSfdZ7ZL6W3idm2JaMTP93RwmCdo
    - sk: unencrypted:edsk4DqHX7tUwsKPesv4iJyNJRaLu7ezZMDs8N5pwfeAbqtvEzLqx7 (from signatory)

- tz1alias
    - pkh: tz1dSrM2D7XcWPhdZpDxzNkmVLvdWSxApXaR
    - pk: edpkvGfYw3LyB1UcCahKQk4rF2tvbMUk8GFiTuMjL75uGXrpvKXhjn
    - sk: unencrypted:edsk4BL896eCJ9t7ZPCdvSq1PKJB9MfqDRNYhYBLFQirmn7SWerPU3 (from signatory)

- tz2alias
    - pkh: tz2QPsZoZse4eeahhg5DdfnBDB4VbU1PwgxN
    - pk: sppk7cvVVMRRtYTdriTB6KQqpXZt9TUwSTcpMWq4FwpvG2eVZ56UuHP
    - sk: unencrypted:spsk1XYsTqUsd7LaLs9a8qpmCvLVJeLEZEXkeAZS5dwcKgUZhv3cYw (from signatory)

- tz3alias
    - pkh: tz3ZbCsUveF3Q6WUNkThT1wyJyhPunanaAXK
    - pk: p2pk67wmwXhknDMAtjFJCh1Z65wCemXchB3KYQfDFp2HvDT1S2Z
    - sk: unencrypted:p2sk2rUMnnnFPQCB7DBozkCZrFhiZ87ddrpAHbRcww7dwU2WHYUbci (from signatory)

- tz4alias
    - pkh: tz4XXtsYav3fZz2FSDa7hcx4F8sh8SaDWNME
    - pk: BLpk1nRV5SBB2QCxsiem5Neoywcizr3mkdp167HL1iKFgFvzPhKo4RSy7J8JBh2BgGgVYjNsRGwU
    - sk: unencrypted:BLsk1XMDG3iepYGj15mBWc7dYjrkpVVM4VH3y5DyBCN9iAGrELwRbY (from signatory)

- bootstrap1
    - pkh: tz1KqTpEZ7Yob7QbPE4Hy4Wo8fHG8LhKxZSx
    - pk: edpkuBknW28nW72KG6RoHtYW7p12T6GKc7nAbwYX5m8Wd9sDVC9yav
    - sk: unencrypted:edsk3gUfUPyBSfrS9CCgmCiQsTCHGkviBDusMxDJstFtojtc1zcpsh

- bootstrap2
    - pkh: tz1gjaF81ZRRvdzjobyfVNsAeSC6PScjfQwN
    - pk: edpktzNbDAUjUk697W7gYg2CRuBQjyPxbEg8dLccYYwKSKvkPvjtV9
    - sk: unencrypted:edsk39qAm1fiMjgmPkw1EgQYkMzkJezLNewd7PLNHTkr6w9XA2zdfo

- bootstrap3
    - pkh: tz1faswCTDciRzE4oJ9jn2Vm2dvjeyA9fUzU
    - pk: edpkuTXkJDGcFd5nh6VvMz8phXxU3Bi7h6hqgywNFi1vZTfQNnS1RV
    - sk: unencrypted:edsk4ArLQgBTLWG5FJmnGnT689VKoqhXwmDPBuGx3z4cvwU9MmrPZZ

- bootstrap4
    - pkh: tz1b7tUupMgCNw2cCLpKTkSD1NZzB5TkP2sv
    - pk: edpkuFrRoDSEbJYgxRtLx2ps82UdaYc1WwfS9sE11yhauZt5DgCHbU
    - sk: unencrypted:edsk2uqQB9AY4FvioK2YMdfmyMrer5R8mGFyuaLLFfSRo8EoyNdht3

- bootstrap5
    - pkh: tz1ddb9NMYHZi5UzPdzTZMYQQZoMub195zgv
    - pk: edpkv8EUUH68jmo3f7Um5PezmfGrRF24gnfLpH3sVNwJnV5bVCxL2n
    - sk: unencrypted:edsk4QLrcijEffxV31gGdN2HU7UpyJjA8drFoNcmnB28n89YjPNRFm

- activator
    - sk: unencrypted:edsk31vznjHSSpGExDMHYASz45VZqXN4DPxvsa4hAyY8dHM28cZzp6

---

