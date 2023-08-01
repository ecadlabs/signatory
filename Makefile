GIT_REVISION := $(shell git rev-parse HEAD)
GIT_BRANCH := $(shell git rev-parse --abbrev-ref HEAD)
CONTAINER_TAG ?= $(shell git branch --show-current)

COLLECTOR_PKG = github.com/ecadlabs/signatory/pkg/metrics

PACKAGE_NAME          := github.com/ecadlabs/signatory
GOLANG_CROSS_VERSION  ?= v1.20.6

all: signatory signatory-cli

signatory:
	CGO_ENABLED=1 go build -ldflags "-X $(COLLECTOR_PKG).GitRevision=$(GIT_REVISION) -X $(COLLECTOR_PKG).GitBranch=$(GIT_BRANCH)" ./cmd/signatory
signatory-cli:
	CGO_ENABLED=1 go build -ldflags "-X $(COLLECTOR_PKG).GitRevision=$(GIT_REVISION) -X $(COLLECTOR_PKG).GitBranch=$(GIT_BRANCH)" ./cmd/signatory-cli

.PHONY: container
container: signatory signatory-cli
	docker build -t ecadlabs/signatory:$(CONTAINER_TAG) .

clean:
	rm signatory signatory-cli

.PHONY: release-dry-run
release-dry-run:
	sudo rm -rf ./dist
	docker run \
		--rm \
		--privileged \
		-e CGO_ENABLED=1 \
		-v /var/run/docker.sock:/var/run/docker.sock \
		-v `pwd`:/go/src/$(PACKAGE_NAME) \
		-w /go/src/$(PACKAGE_NAME) \
		goreleaser/goreleaser-cross:${GOLANG_CROSS_VERSION} \
		release \
		--rm-dist \
		--snapshot

.PHONY: release-preview
release-preview:
	docker run \
		--rm \
		--privileged \
		-e CGO_ENABLED=1 \
		-v /var/run/docker.sock:/var/run/docker.sock \
		-v $(HOME)/.docker/config.json:/root/.docker/config.json \
		-v `pwd`:/go/src/$(PACKAGE_NAME) \
		-w /go/src/$(PACKAGE_NAME) \
		goreleaser/goreleaser-cross:${GOLANG_CROSS_VERSION} \
		release \
		--rm-dist \
		--snapshot

.PHONY: release
release:
	@if [ ! -f ".env" ]; then \
		echo ".env file is required for release";\
		exit 1;\
	fi
	docker run \
		--rm \
		--privileged \
		-e CGO_ENABLED=1 \
		--env-file .env \
		-v /var/run/docker.sock:/var/run/docker.sock \
		-v $(HOME)/.docker:/root/.docker \
		-v `pwd`:/go/src/$(PACKAGE_NAME) \
		-w /go/src/$(PACKAGE_NAME) \
		goreleaser/goreleaser-cross:${GOLANG_CROSS_VERSION} \
		release \
		--rm-dist \
		--skip-validate
