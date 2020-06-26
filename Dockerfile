FROM alpine:3
RUN apk --no-cache add ca-certificates
COPY ./signatory /bin
COPY ./signatory-cli /bin

ENTRYPOINT ["/bin/signatory"]

