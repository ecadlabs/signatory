GIT_REVISION := $(shell git rev-parse HEAD)
GIT_BRANCH := $(shell git rev-parse --abbrev-ref HEAD)
CONTAINER_TAG ?= $(shell git branch --show-current)

COLLECTOR_PKG = github.com/ecadlabs/signatory/pkg/metrics


all: signatory signatory-cli

signatory:
	CGO_ENABLED=1 go build -ldflags "-X $(COLLECTOR_PKG).GitRevision=$(GIT_REVISION) -X $(COLLECTOR_PKG).GitBranch=$(GIT_BRANCH)" ./cmd/signatory
signatory-cli:
	CGO_ENABLED=1 go build -ldflags "-X $(COLLECTOR_PKG).GitRevision=$(GIT_REVISION) -X $(COLLECTOR_PKG).GitBranch=$(GIT_BRANCH)" ./cmd/signatory-cli

build:
	docker build -t sig:make -f Dockerfile .
	docker run -it --rm -v ${PWD}:/root sig:make
deploy:
	docker build -t ghcr.io/ecadlabs/signatory:$(CONTAINER_TAG) -f Dockerfile.Deploy .
	
clean:
	rm signatory signatory-cli
