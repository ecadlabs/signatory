FROM golang:alpine AS build-env

RUN apk update
RUN apk add build-base

WORKDIR  /go/src/github.com/ecadlabs/signatory
ADD . .
RUN go build -o sig

# final stage
FROM alpine
RUN apk --no-cache add ca-certificates
WORKDIR /app
COPY --from=build-env /go/src/github.com/ecadlabs/signatory/sig /app/
ENTRYPOINT /app/sig