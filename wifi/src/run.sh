#!/bin/bash

mkfifo /tmp/f

#stdbuf -o0 -i0 -e0 cat /tmp/f | stdbuf -o0 -i0 -e0 ./solve.py | stdbuf -o0 -i0 -e0 tee /tmp/log.txt | stdbuf -o0 -i0 -e0 nc 20.25.97.145 10110 | stdbuf -o0 -i0 -e0 tee /tmp/f
socat exec:./solve.py tcp-connect:20.25.97.145:10110
