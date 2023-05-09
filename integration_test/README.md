# Integration test

The tests in this folder use a docker compose file to orchestrate the starting of `Signatory`, `flextesa` and `tezos` containers.

The version of Signatory that is run is defined by an environment variable named `IMAGE`. 

The `octez-client` that is run by the tests is provided by the `tezos` container, not the `octez-client` that is onboard the `flextesa` image, so that official `tezos` image releases can be used.  The version of `tezos` container is defined by an environment variable named `OCTEZ_VERSION`. 

Currently, it is always the `latest` version of the `flextesa` image that is run by the tests, which protocol the testnet runs is defined in the script `flextesa.sh`

# Running the tests

Pull the images for the version and architecture that suit your needs. Example:
```sh
export SIGY_IMAGE=ghcr.io/ecadlabs/signatory:v1.0.0-beta3-arm64
export OCTEZ_VERSION=arm64_v16.0-rc3
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
IMAGE=$SIGY_IMAGE OCTEZ_VERSION=$OCTEZ_VERSION go test ./...
```

Or, just run a single test:
```sh
IMAGE=$SIGY_IMAGE OCTEZ_VERSION=$OCTEZ_VERSION go test -run ^TestJWTHappyPath
```

Stop the stack when you are done:
```sh
IMAGE=$SIGY_IMAGE OCTEZ_VERSION=$OCTEZ_VERSION docker compose down
```
