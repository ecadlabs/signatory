FROM ubuntu:22.04
COPY ./signatory /bin
COPY ./signatory-cli /bin

ENTRYPOINT ["/bin/signatory"]

