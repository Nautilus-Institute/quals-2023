#!/bin/bash

if [ "$#" -ne 2 ]; then
    echo "./run_prog <program.license> <program.bin>"
    exit -1
fi

PWD=$(pwd)

docker run -v $PWD/data:/data --rm -it multiarch/qemu-user-static:x86_64-aarch64-6.1.0-8 /data/init_drm -l $1 /data/run_prog $2
