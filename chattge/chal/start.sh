#!/bin/bash

wine regedit.exe "wine.reg"

echo > console.log
tail -f console.log &

xvfb-run -a python3 ./start.py -mod chattge -listen 28080 -host "$HOSTNAME"

kill -9 %1
