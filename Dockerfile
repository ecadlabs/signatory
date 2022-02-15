FROM alpine:3 AS build

RUN apk update
RUN apk upgrade
RUN apk add --update alpine-sdk
RUN apk add --update go
RUN apk add linux-headers
RUN apk add --update make

WORKDIR /root

ENTRYPOINT ["make"]