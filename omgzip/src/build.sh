#!/bin/bash

figlet -w 200 < flag.txt > corpus/flag
tar cvf data.tar corpus
python3 omgzip data.tar
zip omg.zip omgzip data.tar.omgzip

# Copy file so it can be used on the server
# It will end up in /opt/challenge
cp omg.zip ../build/omg.zip
