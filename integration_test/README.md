## Integration test

The tests in this folder use a docker compose file to orchestrate the starting of `Signatory`, `flextesa` and `tezos` containers.  

The version of Signatory that is run is defined by an environment variable named `IMAGE`.

The `octez-client` that is run by the tests is provided by the `tezos` container, not the `octez-client` that is onboard the `flextesa` image, so that official `tezos` image releases can be used.  The version of `tezos` container is defined by an environment variable named `OCTEZ_VERSION`.

Currently, it is always the `latest` version of the `flextesa` image that is run by the tests, which protocol the testnet runs is defined in the script `flextesa.sh`

## Pulling the images

Pre-release Signatory images are available in [github container registry](https://github.com/ecadlabs/signatory/pkgs/container/signatory)
Official image releases are available in [dockerhub](https://hub.docker.com/r/ecadlabs/signatory/tags)
If you get a 404 from the github container registry, you can request access from an admin.

### Github container registry authentication setup

If this is your first time pulling an image from github packages, then you'll need to configure a [Personal Access Token PAT (classic)](https://github.com/settings/tokens). The only access you should grant the PAT is `read:packages`.  With that token as the value of env var `$PAT`, you can now login:

```sh
echo $PAT |docker login ghcr.io -u <your_github_name> --password-stdin
```

## Running the tests

Pull the images for the version and architecture that suit your needs from [flextesa](https://hub.docker.com/r/oxheadalpha/flextesa/tags), [tezos](https://hub.docker.com/r/tezos/tezos/tags), [signatory (pre-release)](https://github.com/ecadlabs/signatory/pkgs/container/signatory/versions), or [signatory (release)](https://hub.docker.com/r/ecadlabs/signatory/tags)

Example:

```sh
export SIGY_IMAGE=ghcr.io/ecadlabs/signatory:main-arm64
export OCTEZ_VERSION=arm64_v17.0-beta1
docker pull oxheadalpha/flextesa:latest
docker pull tezos/tezos:$OCTEZ_VERSION
docker pull $SIGY_IMAGE
```

Next, start the stack:

```sh
cd integration_test
IMAGE=$SIGY_IMAGE OCTEZ_VERSION=$OCTEZ_VERSION docker compose up -d --wait
```

Run all the tests:

```sh
go clean -testcache && IMAGE=$SIGY_IMAGE OCTEZ_VERSION=$OCTEZ_VERSION go test ./...
```

Or, just run a single test:

```sh
go clean -testcache && IMAGE=$SIGY_IMAGE OCTEZ_VERSION=$OCTEZ_VERSION go test -run ^TestOperationAllowPolicy
```

Stop the stack when you are done:

```sh
IMAGE=$SIGY_IMAGE OCTEZ_VERSION=$OCTEZ_VERSION docker compose down
```

## Notes to the operator

Some tests in this folder make edits to `signatory.yaml` configuration and restart the Signatory service. By design, tests that do this shall clean up after themselves by restoring the copy of the file that is in the code repository.  If `git status` after a test run shows you have modifications to the `signatory.yaml` file, then that would mean a test is failing to clean up after itself and should be corrected.
