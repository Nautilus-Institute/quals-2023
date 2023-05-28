#!/bin/bash -x

set -e

# My stupid macbook has ARM docker and can't run wine i386 properly
# Are you saying running windows in linux in macos was a bad idea?
# Are you saying also doing that via qemu user system is dumb?
export DOCKER_HOST="ssh://ctf@127.0.0.1"

docker compose build

# Copy images locally for manual poking
IMAGE=$(docker create chattge-chattge:latest)
docker cp $IMAGE:/handout.tar.gz handout.tar.gz
docker cp $IMAGE:/server.tar.gz server.tar.gz
docker container rm $IMAGE

docker compose up
