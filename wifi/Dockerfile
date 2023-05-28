FROM ubuntu

RUN apt-get update && apt-get install -y python3 \
  tmux \
  tcpdump \
  iw \
  nano \
  netcat \
  socat \
  hostapd \
  wpasupplicant \
  pip \
  inetutils-ping \
  iproute2 \
  net-tools

RUN pip3 install scapy

COPY src/pyaes /pyaes/
COPY src/ap.py /
COPY src/gost.py /

CMD ["/ap.py"]
# socat exec:./ap.py tcp-listen:localhost:4444
