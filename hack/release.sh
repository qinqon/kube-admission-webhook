#!/bin/bash -e

organization=qinqon
project=kube-admission-webhook
user=$organization

description=version/description
tag=$(hack/version.sh)

git tag $tag
git push https://github.com/$organization/$project $tag

$GITHUB_RELEASE release -u $user -r $project \
    --tag $tag \
	--name $tag \
    --description "$(cat $description)"
