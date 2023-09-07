#!/bin/bash -xe

version=v1.42.1
timeout=5m

go run github.com/golangci/golangci-lint/cmd/golangci-lint@$version run --timeout $timeout

