FROM ubuntu:22.04


RUN apt-get update && apt-get install -y python3 python3-pip socat netcat
RUN pip3 install scapy  stdbuf
#RUN apt-get install stdbuf

COPY . /

