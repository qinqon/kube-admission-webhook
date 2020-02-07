SHELL := /bin/bash

BIN_DIR = $(CURDIR)/build/_output/bin/

export GOFLAGS=-mod=vendor
export GO111MODULE=on
export GOROOT=$(BIN_DIR)/go/
export GOBIN=$(GOROOT)/bin/
export PATH := $(GOROOT)/bin:$(PATH)

GO ?= $(GOBIN)/go
GOFMT ?= $(GOBIN)/gofmt

export GITHUB_RELEASE := $(GOBIN)/github-release

all: test

$(GITHUB_RELEASE): $(GO)
	$(GO) install ./vendor/github.com/aktau/github-release

$(GO):
	hack/install-go.sh $(BIN_DIR)

$(GOFMT): $(GO)

format: $(FMT)
	hack/whitespace.sh format
	$(GOFMT) -w ./pkg

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
