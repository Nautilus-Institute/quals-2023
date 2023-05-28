#!/bin/bash

clang -Wall -Wshadow -Wextra -std=c99 -Wl,-z,norelro -D_GNU_SOURCE -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0 -m32  open-house.c -o open-house
strip open-house

cp open-house ../build/challenge
