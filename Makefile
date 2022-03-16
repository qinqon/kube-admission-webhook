SHELL := /bin/bash

BIN_DIR = $(CURDIR)/build/_output/bin/

WHAT ?= ./pkg/...

KUBEVIRT_PROVIDER=kind-k8s-1.14.2

CLUSTER_DIR ?= kubevirtci/cluster-up/
KUBECONFIG ?= kubevirtci/_ci-configs/$(KUBEVIRT_PROVIDER)/.kubeconfig
export KUBECTL ?= $(CLUSTER_DIR)/kubectl.sh
CLUSTER_UP ?= $(CLUSTER_DIR)/up.sh
CLUSTER_DOWN ?= $(CLUSTER_DIR)/down.sh
CLI ?= $(CLUSTER_DIR)/cli.sh
export SSH ?= $(CLUSTER_DIR)/ssh.sh

export GITHUB_RELEASE := $(GOBIN)/github-release

install_kubevirtci := hack/install-kubevirtci.sh

all: test

$(CLUSTER_DIR)/%: $(install_kubevirtci)
	$(install_kubevirtci)

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

cluster-up: $(CLUSTER_UP)
	$(CLUSTER_UP)

cluster-down: $(CLUSTER_DOWN)
	$(CLUSTER_DOWN)

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
