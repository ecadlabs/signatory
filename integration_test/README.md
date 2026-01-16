## Signatory Integration Test

### Quick Start

Run integration tests with a single command:

```sh
# From repo root
make integration-test

# Or from this directory
./run-tests.sh
```

The script automatically:
- Detects your architecture (amd64/arm64)
- Builds the signatory image with your local changes
- Creates required placeholder config files
- Starts the test stack
- Runs the tests
- Offers to stop the stack when done

#### Other useful commands

```sh
# Build only (no tests)
./run-tests.sh build

# Start stack only
./run-tests.sh up

# Stop stack
./run-tests.sh down

# View logs
./run-tests.sh logs

# Open shell in container
./run-tests.sh shell

# Run specific test
./run-tests.sh .env.current TestMetrics

# Use next protocol
./run-tests.sh .env.next
```

---

### Folder Organization

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

## About Integration test

The tests in this folder use a docker compose file to orchestrate the starting of `Signatory`, `tezos`, and `speculos` containers.  

The version of Signatory that is run is defined by an environment variable named `IMAGE`.

The `octez-client` that is run by the tests is provided by the `tezos` container. The version of `tezos` container is defined by an environment variable named `OCTEZ_VERSION`.

The economic protocol run by tezos sandbox is defined by an environment variable named `PROTOCOL`

## Pulling the images

Pre-release Signatory images are available in [github container registry](https://github.com/ecadlabs/signatory/pkgs/container/signatory)
Official image releases are available in [dockerhub](https://hub.docker.com/r/ecadlabs/signatory/tags)
If you get a 404 from the github container registry web console, you can request access from an admin.

[tezos](https://hub.docker.com/r/tezos/tezos/tags) image is used

A custom [speculos](https://hub.docker.com/r/stephengaudet/tezoswalletemu) image is used, this image has the tezos wallet installed.

## Github container registry authentication setup

If this is your first time pulling an image from github packages, then you'll need to configure a [Personal Access Token PAT (classic)](https://github.com/settings/tokens). The only access you should grant the PAT is `read:packages`.  With that token as the value of env var `$PAT`, you can now login:

```sh
echo $PAT |docker login ghcr.io -u <your_github_name> --password-stdin
```

## Running the tests

The tests are run in a [github workflow](/.github/workflows/build.yaml) and so the workflow should be consulted to learn how to run the tests locally.  A more verbose explanation:

```sh
cd integration_test
```

Exporting the Environment Variables used by the test is required.
Firstly, set `ARCH` to match your docker host. On a `x86_64` host:

```sh
export ARCH=amd64
```

use `arm64` on a macbook m1 host

Next, decide the version of Signatory you want to test.
using main branch:

```sh
export IMAGE=ghcr.io/ecadlabs/signatory:main-${ARCH}
```

Next, choose the economic protocol version run by flextesa, and the version of octez-octez client.

Choose the set of env var to use from the files `.env.current`, `.env.next`.  Use `current` if you'd like the economic protocol run by flextesa to match mainnet, use `next` if you'd like the next protocol instead.

So, to set the env to use mainnet protocol:

```sh
. ./.env.current
```

Likewise, to set the env to use the next protocol:

```sh
. ./.env.next
```

### vault env var

Github secrets are used to define vault env var used in github workflows. To run vault tests localhost, one must configure vaults and provide values in the file `.env.vaults` before sourcing it:

```sh
. .env.vaults
```

### using GCP vault

```sh
envsubst < gcp-token-template.json > gcp-token.json
```

### using AZ vault

```sh
echo $VAULT_AZ_SP_KEY |base64 -d >service-principal.key
```

Next, start the stack:

```sh
docker compose up -d --wait --pull always
```

Run all the tests:

```sh
go clean -testcache && go test ./...
```

Or, just run a single test:

```sh
go clean -testcache && go test -run ^TestOperationAllowPolicy
```

To run all tests but not vault tests:

```sh
go clean -testcache && go test $(go list |grep -v vault)
```

Stop the stack when you are done:

```sh
docker compose down
```

## Re-Running Tests

Most tests can be re-run successfully as detailed above.  Some tests (like the `reveal` operation) can only be run once on a chain.  So, when re-running all, stop the stack and bring it up again in between test runs.

## Notes to the operator

Some tests in this folder make edits to `signatory.yaml` configuration and restart the Signatory service. By design, tests that do this shall clean up after themselves by restoring the copy of the file that is in the code repository.  If `git status` after a test run shows you have modifications to the `signatory.yaml` file, then that would mean a test is failing to clean up after itself and should be corrected.  Function `backup_then_update_config()` and `defer restore_config()` should be used by tests that edit config. Likewise, `git status` may show you new files in the `.tezos-client` folder, another indication of a test not cleaning up after itself.  Function `clean_tezos_folder()` should be used by tests that leave state behind in `.tezos-client`.

The PEM file that is used for AZ authentication is stored in env var `VAULT_AZ_SP_KEY` which in github actions is supplied via secret `${{ secrets.INTEGRATIONTEST_VAULT_AZ_SP_KEY }}`.  Because github secrets do not support multiline values, the PEM file content was base64 encoded before entered as the value of the secret.  With the private key in a file named `service-principal.key` the base64 value is generated by:

```sh
cat service-principal.key|base64 -e >service-principal.base64
```

The string value in file `service-principal.base64` is then used in env var `VAULT_AZ_SP_KEY`.
