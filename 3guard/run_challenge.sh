#!/bin/bash

python3 /opt/guard1.py &
python3 /opt/guard2.py &
python3 /opt/guard3.py &

/bin/sleep 2

#flag is in /opt/flag.txt

python3 -u /opt/main.py