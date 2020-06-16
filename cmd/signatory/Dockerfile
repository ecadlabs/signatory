FROM golang:1.14-alpine AS build-env

ENV COLLECTOR_PKG="github.com/ecadlabs/signatory/pkg/metrics"
ENV GO111MODULE="on"
WORKDIR /build/signatory
RUN apk update && apk add git openssh bash
ADD . .
RUN go build -ldflags "-X ${COLLECTOR_PKG}.GitRevision=${GIT_REVISION} -X ${COLLECTOR_PKG}.GitBranch=${GIT_BRANCH} -X ${COLLECTOR_PKG}.GitVersion=${GIT_VERSION}" ./cmd/signatory

# final stage
FROM alpine
RUN apk --no-cache add ca-certificates
WORKDIR /app
COPY --from=build-env /build/signatory/signatory /app/
ENTRYPOINT /app/signatory
