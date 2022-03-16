SHELL := /bin/bash
BIN_DIR = $(CURDIR)/build/_output/bin/
WHAT ?= ./pkg/...

all: test

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

.PHONY: \
	test \
	vendor \
	format \
	vet \
	build
