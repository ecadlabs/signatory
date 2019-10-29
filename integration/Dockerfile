FROM tezos/tezos:babylonnet as tezos

FROM golang:1.13.2-buster

WORKDIR /circleci/integration-tests/signatory
ENV GO111MODULE="on"

RUN apt-get update && apt-get install -y build-essential

RUN apt-get install -y curl apt-transport-https lsb-release software-properties-common \
    && curl -fsSL https://download.docker.com/linux/$(lsb_release -is | tr '[:upper:]' '[:lower:]')/gpg | apt-key add - 2>/dev/null \
    && add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/$(lsb_release -is | tr '[:upper:]' '[:lower:]') $(lsb_release -cs) stable" \
    && apt-get update \ 
    && apt-get install -y docker-ce-cli

COPY --from=tezos /usr/local/bin/tezos-client /usr/local/bin/tezos-client

COPY . .

RUN go mod download

ENTRYPOINT ["go", "test", "-v", "--count", "1", "./integration"]