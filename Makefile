GIT_REVISION := $(shell git rev-parse HEAD)
GIT_BRANCH := $(shell git rev-parse --abbrev-ref HEAD)

COLLECTOR_PKG = github.com/ecadlabs/signatory/pkg/metrics
.PHONY: signatory exporter
signatory:
	go build -ldflags "-X $(COLLECTOR_PKG).GitRevision=$(GIT_REVISION) -X $(COLLECTOR_PKG).GitBranch=$(GIT_BRANCH)" ./cmd/signatory
exporter:
	go build -ldflags "-X $(COLLECTOR_PKG).GitRevision=$(GIT_REVISION) -X $(COLLECTOR_PKG).GitBranch=$(GIT_BRANCH)" ./cmd/exporter