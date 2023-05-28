#!/bin/bash

echo "flag{Test flag goes here}" > flag.txt

wine regedit.exe "wine.reg"
xvfb-run -a python3 ./start.py -mod chattge -compileall

mkdir server
cp -R chattge flag.txt main.cs start.py start.sh ChatTGE.exe wine.reg server

mkdir handout
mkdir handout/chattge
cp chattge/*.dso chattge/index.html handout/chattge
cp console.log flag.txt main.cs ChatTGE.exe handout
cp /root/.wine/drive_c/windows/system32/kernel32.dll handout

cd server
tar cvzf /server.tar.gz .
cd ..
cd handout
tar cvzf /handout.tar.gz .
cd ..
