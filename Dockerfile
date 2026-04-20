FROM golang:1.26.2-bookworm AS builder
ADD . /signatory
WORKDIR /signatory
RUN make

FROM ubuntu:24.04
WORKDIR /signatory
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /signatory/signatory.yaml /signatory/signatory.yaml
COPY --from=builder /signatory/signatory /usr/bin/signatory
COPY --from=builder /signatory/signatory-cli /usr/bin/signatory-cli

# Create non-root user with configurable UID/GID
ARG UID=10000
ARG GID=10000
RUN groupadd -g ${GID} signatory && \
    useradd -u ${UID} -g signatory -m signatory && \
    mkdir -p /var/lib/signatory /etc/signatory && \
    chown -R signatory:signatory /var/lib/signatory /etc/signatory

USER signatory
ENTRYPOINT ["/usr/bin/signatory"]
CMD [ "-c", "/signatory/signatory.yaml" ]
