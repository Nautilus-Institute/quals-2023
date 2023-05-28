#!/bin/bash

CHALLENGE_NAME=$(basename $(pwd))

# Slugify challenge name
CHALLENGE_NAME=$(echo $CHALLENGE_NAME | iconv -t ascii//TRANSLIT | sed -E -e 's/[^[:alnum:]]+/-/g' -e 's/^-+|-+$//g' | tr '[:upper:]' '[:lower:]')

docker run --rm -it \
    --name "${CHALLENGE_NAME}-challenge" \
    "${CHALLENGE_NAME}-challenge"

