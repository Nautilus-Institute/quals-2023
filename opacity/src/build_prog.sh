#!/bin/bash

if [ "$#" -ne 3 ]; then
    echo "./build_prog <program.license> <program name> <program.bin>"
    exit -1
fi

set -e
set -x

docker run -v $(pwd)/data:/data --rm -it multiarch/qemu-user-static:x86_64-aarch64-6.1.0-8 /data/init_drm -l $1 /data/build_prog $2 $3
