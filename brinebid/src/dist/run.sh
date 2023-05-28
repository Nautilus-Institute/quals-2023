#!/bin/bash
docker build -t dcq2023-brine-bid .

mkdir -p wallet
chmod 777 wallet

echo "Running on ws://0.0.0.0:8080"
docker run --rm \
    -p 8080:8080 \
    --name brine-bid \
    -v $(pwd)/wallet:/wallet \
    -v $(pwd)/properties:/properties/auction:ro \
    -d dcq2023-brine-bid

