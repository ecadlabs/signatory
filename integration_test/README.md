## Integration test

The tests in this folder use a docker compose file to orchestrate the starting of `Signatory`, `flextesa`, `tezos`, and `speculos` containers.  

The version of Signatory that is run is defined by an environment variable named `IMAGE`.

The `octez-client` that is run by the tests is provided by the `tezos` container. The version of `tezos` container is defined by an environment variable named `OCTEZ_VERSION`.

Currently, it is always the `latest` version of the `flextesa` image that is run by the tests.  The economic protocol run by flextesa is defined by an environment variable named `PROTOCOL`

## Pulling the images

Pre-release Signatory images are available in [github container registry](https://github.com/ecadlabs/signatory/pkgs/container/signatory)
Official image releases are available in [dockerhub](https://hub.docker.com/r/ecadlabs/signatory/tags)
If you get a 404 from the github container registry web console, you can request access from an admin.

[flextesa](https://hub.docker.com/r/oxheadalpha/flextesa/tags) image is used.

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
