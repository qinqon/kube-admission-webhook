SHELL := /bin/bash
BIN_DIR = $(CURDIR)/build/_output/bin/
WHAT ?= ./pkg/...

all: test

lint:
	hack/lint.sh

testenv:
	hack/setup-testenv.sh

test: testenv
	KUBEBUILDER_ASSETS=$(BIN_DIR) go test $(WHAT) -timeout 2m -ginkgo.v -ginkgo.noColor=false  -test.v

build:
	go build ./pkg/...

.PHONY: \
	test \
	vendor \
	format \
	vet \
	build
