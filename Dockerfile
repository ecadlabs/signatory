FROM ubuntu:22.04
RUN apt-get update &&\
    apt-get install -y curl apt-transport-https &&\
    apt-get clean

COPY ./signatory /bin
COPY ./signatory-cli /bin

ENTRYPOINT ["/bin/signatory"]

