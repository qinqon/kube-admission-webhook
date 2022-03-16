SHELL := /bin/bash

BIN_DIR = $(CURDIR)/build/_output/bin/

WHAT ?= ./pkg/...

export GITHUB_RELEASE := $(GOBIN)/github-release

all: test

$(GITHUB_RELEASE):
	go install ./vendor/github.com/github-release/github-release

format: $(FMT)
	hack/whitespace.sh format
	gofmt -w ./pkg

vet:
	go vet ./pkg/...

testenv:
	hack/setup-testenv.sh

test: testenv
	KUBEBUILDER_ASSETS=$(BIN_DIR) go test $(WHAT) -timeout 2m -ginkgo.v -ginkgo.noColor=false  -test.v

build:
	go build ./pkg/...

vendor:
	go mod tidy
	go mod vendor

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
	vet \
	build
