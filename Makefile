GIT_REVISION := $(shell git rev-parse HEAD)
GIT_BRANCH := $(shell git rev-parse --abbrev-ref HEAD)
CONTAINER_TAG ?= $(shell git branch --show-current)

COLLECTOR_PKG = github.com/ecadlabs/signatory/pkg/metrics


all: signatory signatory-cli

signatory:
	CGO_ENABLED=0 go build -ldflags "-X $(COLLECTOR_PKG).GitRevision=$(GIT_REVISION) -X $(COLLECTOR_PKG).GitBranch=$(GIT_BRANCH)" ./cmd/signatory
signatory-cli:
	CGO_ENABLED=0 go build -ldflags "-X $(COLLECTOR_PKG).GitRevision=$(GIT_REVISION) -X $(COLLECTOR_PKG).GitBranch=$(GIT_BRANCH)" ./cmd/signatory-cli

container:
	docker build -t ghcr.io/ecadlabs/signatory:$(CONTAINER_TAG) .


clean:
	rm signatory signatory-cli
