SHELL := /bin/bash

BIN_DIR = $(CURDIR)/build/_output/bin/

export GOFLAGS=-mod=vendor
export GO111MODULE=on
export GOROOT=$(BIN_DIR)/go/
export GOBIN=$(GOROOT)/bin/
export PATH := $(GOROOT)/bin:$(PATH)

GO ?= $(GOBIN)/go
GOFMT ?= $(GOBIN)/gofmt

KUBEVIRT_PROVIDER=kind-k8s-1.14.2
POD_IMAGE_NAME ?= localhost:5000/qinqon/kube-admission-webhook

CLUSTER_DIR ?= kubevirtci/cluster-up/
KUBECTL ?= $(CLUSTER_DIR)/kubectl.sh
CLUSTER_UP ?= $(CLUSTER_DIR)/up.sh
CLUSTER_DOWN ?= $(CLUSTER_DIR)/down.sh

export GITHUB_RELEASE := $(GOBIN)/github-release

install_kubevirtci := hack/install-kubevirtci.sh

all: test

$(CLUSTER_DIR)/%: $(install_kubevirtci)
	$(install_kubevirtci)

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

pod: $(GO)
	$(GO) build -o $(BIN_DIR) ./pkg/... ./test/pod
	docker build . -f test/pod/Dockerfile -t $(POD_IMAGE_NAME)

push: pod
	docker push $(POD_IMAGE_NAME)

vendor:
	$(GO) mod tidy
	$(GO) mod vendor

cluster-up: $(CLUSTER_UP)
	$(CLUSTER_UP)

cluster-down: $(CLUSTER_DOWN)
	$(CLUSTER_DOWN)

cluster-sync: push
	$(KUBECTL) delete --ignore-not-found=true -f test/pod
	$(KUBECTL) apply -f test/pod

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
