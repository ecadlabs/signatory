FROM golang:1.24-bullseye AS builder
RUN apt-get update && apt-get install
ADD . /signatory
WORKDIR /signatory
RUN make

FROM debian:buster-slim
WORKDIR /signatory
RUN apt update -y \
    && apt install -y curl apt-transport-https\
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /signatory/signatory.yaml /signatory/signatory.yaml
COPY --from=builder /signatory/signatory /usr/bin/signatory
COPY --from=builder /signatory/signatory-cli /usr/bin/signatory-cli

# Create non-root user with configurable UID/GID
ARG UID=1000
ARG GID=1000
RUN groupadd -g ${GID} signatory && \
    useradd -u ${UID} -g signatory -m signatory && \
    mkdir -p /var/lib/signatory /etc/signatory && \
    chown -R signatory:signatory /var/lib/signatory /etc/signatory

USER signatory
ENTRYPOINT ["/usr/bin/signatory"]
CMD [ "-c", "/signatory/signatory.yaml" ]
