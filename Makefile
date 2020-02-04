export GOFLAGS=-mod=vendor
export GO111MODULE=on
export GOBIN=~/go/bin

GOVERSION=$(shell hack/go-version.sh)
GO ?= $(GOBIN)/go$(GOVERSION)
export GITHUB_RELEASE := $(GOBIN)/github-release

all: test

$(GITHUB_RELEASE): $(GO)
	$(GO) install ./vendor/github.com/aktau/github-release

$(GO):
	hack/install-go.sh $(GOVERSION)

format: whitespace-format gofmt

vet: $(GO)
	$(GO) vet ./pkg/...

whitespace-format:
	hack/whitespace.sh format

gofmt: $(GO)
	$(GO) fmt ./pkg/...

whitespace-check:
	hack/whitespace.sh check

gofmt-check: $(GO)
	test -z "`$(GOFMT) -l pkg/ `" || ($(GOFMT) -l pkg/ && exit 1)

test: $(GO) vet format
	$(GO) test ./pkg/...

vendor:
	$(GO) mod tidy
	$(GO) mod vendor

release:
	hack/release.sh

.PHONY: \
	test \
	vendor
