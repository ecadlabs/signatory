FROM golang:1.14-alpine AS build-env

ENV COLLECTOR_PKG="github.com/ecadlabs/signatory/pkg/metrics"
ENV GO111MODULE="on"
WORKDIR /build/signatory
RUN apk update && apk add git openssh bash
ADD . .
RUN go build -ldflags "-X ${COLLECTOR_PKG}.GitRevision=${GIT_REVISION} -X ${COLLECTOR_PKG}.GitBranch=${GIT_BRANCH} -X ${COLLECTOR_PKG}.GitVersion=${GIT_VERSION}" ./cmd/signatory
RUN go build -ldflags "-X ${COLLECTOR_PKG}.GitRevision=${GIT_REVISION} -X ${COLLECTOR_PKG}.GitBranch=${GIT_BRANCH} -X ${COLLECTOR_PKG}.GitVersion=${GIT_VERSION}" ./cmd/signatory-cli


# final stage
FROM alpine:3
RUN apk --no-cache add ca-certificates
COPY --from=build-env /build/signatory/signatory /bin
COPY --from=build-env /build/signatory/signatory-cli /bin

ENTRYPOINT ["/app/signatory"]
