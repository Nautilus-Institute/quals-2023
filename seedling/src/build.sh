#!/bin/bash

clang -O2 -o verify verify.c
strip -S verify
