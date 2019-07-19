FROM golang:alpine AS build-env

ENV COLLECTOR_PKG="github.com/ecadlabs/signatory/metrics"
ENV GO111MODULE="on"

WORKDIR /build/signatory
ADD . .
RUN go build -o sig -ldflags "-X ${COLLECTOR_PKG}.GitRevision=${GIT_REVISION} -X ${COLLECTOR_PKG}.GitBranch=${GIT_BRANCH} -X ${COLLECTOR_PKG}.GitVersion=${GIT_VERSION}"

# final stage
FROM alpine
RUN apk --no-cache add ca-certificates
WORKDIR /app
COPY --from=build-env /build/signatory/sig /app/
ENTRYPOINT /app/sig