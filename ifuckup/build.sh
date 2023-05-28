#!/bin/bash

gcc ifuckup.c WELL512a.c -nostdlib -fPIC -fpic -o challenge -Wall -Wa,--no-warn -m32 -Os -static -fno-stack-protector -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0 -Wl,-z,norelro
strip -s challenge

# Copy file so it can be used on the server
# It will end up in /opt/challenge
cp challenge ../build/.
