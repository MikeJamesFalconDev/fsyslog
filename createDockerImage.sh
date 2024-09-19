#!/bin/bash

GIT_STATUS=`git status | grep -E "Changes not staged|Untracked files|Changes to be committed"`

if [ -n "$GIT_STATUS" ];then
	echo "Please push latest changes to git and tag version before building docker image"
	exit 1
fi

GIT_TAG_VERSION=`git describe --abbrev=0`
GIT_DESCRIBE=`git describe`

if [ $GIT_TAG_VERSION != $GIT_DESCRIBE ];then
	echo 'There have been commits since last version. Please tag and push version. git tag -a v0.0.1 -m "my version 0.0.1"'
	exit 1
fi

GIT_TAG_VERSION=${GIT_TAG_VERSION#v}

set -x
sudo docker build . -t mikefalcondev/fsyslog:$GIT_TAG_VERSION
sudo docker push mikefalcondev/fsyslog:$GIT_TAG_VERSION
