#!/bin/bash
set -ev

TRAVIS_BRANCH=$1
REPO=$2
VERSION=$3
DOCKER_VESION=$4
DOCKER_FILE=$5

if [ "$TRAVIS_BRANCH" == "master" ]; then
  TAG="latest";
else
  TAG=$TRAVIS_BRANCH;
fi

docker build -f dockers/$DOCKER_FILE . -t $REPO

docker tag $REPO $REPO:$TAG
docker tag $REPO $REPO:$VERSION
docker tag $REPO $REPO:$DOCKER_VESION

if [ "$TRAVIS_BRANCH" == "master" ] && [ "$DOCKER_USER" != "" ] && [  "$DOCKER_PASS" != "" ]; then
  docker login -u "$DOCKER_USER" -p "$DOCKER_PASS";
  docker push $REPO ;
fi
