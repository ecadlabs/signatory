# Multi-stage Dockerfile for building signatory for integration tests
# This builds inside the container, avoiding cross-compilation issues on macOS

FROM golang:1.25-bookworm AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG GIT_REVISION=unknown
ARG GIT_BRANCH=unknown
RUN CGO_ENABLED=1 go build -ldflags "-X github.com/ecadlabs/signatory/pkg/metrics.GitRevision=${GIT_REVISION} -X github.com/ecadlabs/signatory/pkg/metrics.GitBranch=${GIT_BRANCH}" -o /signatory ./cmd/signatory
RUN CGO_ENABLED=1 go build -ldflags "-X github.com/ecadlabs/signatory/pkg/metrics.GitRevision=${GIT_REVISION} -X github.com/ecadlabs/signatory/pkg/metrics.GitBranch=${GIT_BRANCH}" -o /signatory-cli ./cmd/signatory-cli

FROM ubuntu:24.04
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl wget && rm -rf /var/lib/apt/lists/*
ARG TARGETARCH
RUN if [ "$TARGETARCH" = "amd64" ]; then \
    wget -q https://s3.amazonaws.com/cloudhsmv2-software/CloudHsmClient/Noble/cloudhsm-pkcs11_latest_u24.04_amd64.deb && \
    apt install -y ./cloudhsm-pkcs11_latest_u24.04_amd64.deb && \
    rm cloudhsm-pkcs11_latest_u24.04_amd64.deb; \
    elif [ "$TARGETARCH" = "arm64" ]; then \
    wget -q https://s3.amazonaws.com/cloudhsmv2-software/CloudHsmClient/Noble/cloudhsm-pkcs11_latest_u24.04_arm64.deb && \
    apt install -y ./cloudhsm-pkcs11_latest_u24.04_arm64.deb && \
    rm cloudhsm-pkcs11_latest_u24.04_arm64.deb; \
    fi
ENV PATH="/opt/cloudhsm/bin:${PATH}"

ARG UID=10000
ARG GID=10000
RUN groupadd -g ${GID} signatory && \
    useradd -u ${UID} -g signatory -m signatory && \
    mkdir -p /var/lib/signatory /etc/signatory && \
    chown -R signatory:signatory /var/lib/signatory /etc/signatory

COPY --from=builder /signatory /bin/signatory
COPY --from=builder /signatory-cli /bin/signatory-cli

USER signatory
ENTRYPOINT ["/bin/signatory"]
