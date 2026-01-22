# Multi-stage Dockerfile for building signatory for integration tests
# This builds inside the container, avoiding cross-compilation issues on macOS

FROM golang:1.24-bookworm AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG GIT_REVISION=unknown
ARG GIT_BRANCH=unknown
RUN CGO_ENABLED=1 go build -ldflags "-X github.com/ecadlabs/signatory/pkg/metrics.GitRevision=${GIT_REVISION} -X github.com/ecadlabs/signatory/pkg/metrics.GitBranch=${GIT_BRANCH}" -o /signatory ./cmd/signatory
RUN CGO_ENABLED=1 go build -ldflags "-X github.com/ecadlabs/signatory/pkg/metrics.GitRevision=${GIT_REVISION} -X github.com/ecadlabs/signatory/pkg/metrics.GitBranch=${GIT_BRANCH}" -o /signatory-cli ./cmd/signatory-cli

FROM ubuntu:22.04
RUN apt-get update && apt-get install -y curl apt-transport-https wget && rm -rf /var/lib/apt/lists/*
ARG TARGETARCH
RUN if [ "$TARGETARCH" = "amd64" ]; then \
    wget -q https://s3.amazonaws.com/cloudhsmv2-software/CloudHsmClient/Jammy/cloudhsm-pkcs11_latest_u22.04_amd64.deb && \
    apt install -y ./cloudhsm-pkcs11_latest_u22.04_amd64.deb && \
    rm cloudhsm-pkcs11_latest_u22.04_amd64.deb; \
    elif [ "$TARGETARCH" = "arm64" ]; then \
    wget -q https://s3.amazonaws.com/cloudhsmv2-software/CloudHsmClient/Jammy/cloudhsm-pkcs11_latest_u22.04_arm64.deb && \
    apt install -y ./cloudhsm-pkcs11_latest_u22.04_arm64.deb && \
    rm cloudhsm-pkcs11_latest_u22.04_arm64.deb; \
    fi
ENV PATH="/opt/cloudhsm/bin:${PATH}"

ARG UID=1000
ARG GID=1000
RUN groupadd -g ${GID} signatory && \
    useradd -u ${UID} -g signatory -m signatory && \
    mkdir -p /var/lib/signatory && \
    chown -R signatory:signatory /var/lib/signatory

COPY --from=builder /signatory /bin/signatory
COPY --from=builder /signatory-cli /bin/signatory-cli

USER signatory
ENTRYPOINT ["/bin/signatory"]
