FROM ubuntu:23.10
RUN apt-get update
RUN apt-get install -y curl apt-transport-https
RUN apt-get clean

COPY ./signatory /bin
COPY ./signatory-cli /bin

ENTRYPOINT ["/bin/signatory"]

