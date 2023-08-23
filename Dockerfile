FROM golang:1.21-bullseye AS builder
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

ENTRYPOINT ["/usr/bin/signatory"]
CMD [ "-c", "/signatory/signatory.yaml" ]
