export GOFLAGS=-mod=vendor
export GO111MODULE=on
export GOBIN=$(HOME)/go/bin

GOVERSION=$(shell hack/go-version.sh)
GO ?= $(GOBIN)/go$(GOVERSION)
export GITHUB_RELEASE := $(GOBIN)/github-release

all: test

$(GITHUB_RELEASE): $(GO)
	$(GO) install ./vendor/github.com/aktau/github-release

$(GO):
	hack/install-go.sh $(GOVERSION)

format:
	hack/whitespace.sh format
	$(GO) fmt ./pkg/...
	test -z "`$(GOFMT) -l pkg/ `" || ($(GOFMT) -l pkg/ && exit 1)

vet: $(GO)
	$(GO) vet ./pkg/...

test: $(GO) vet format
	$(GO) test ./pkg/...

vendor:
	$(GO) mod tidy
	$(GO) mod vendor

prepare-patch:
	./hack/prepare-release.sh patch
prepare-minor:
	./hack/prepare-release.sh minor
prepare-major:
	./hack/prepare-release.sh major

release: $(GITHUB_RELEASE)
	hack/release.sh

.PHONY: \
	test \
	vendor \
	release \
	prepare-patch \
	prepare-minor \
	prepare-major \
	format \
	vet
