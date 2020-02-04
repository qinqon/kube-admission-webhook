#!/bin/bash -xe

version=$(grep "^go " go.mod |awk '{print $2}')

unset GOFLAGS
go get golang.org/dl/go$version
go$version download
