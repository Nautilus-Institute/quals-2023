FROM ubuntu:22.04 AS builder

RUN apt-get update && \
    apt-get install -y figlet zip python3

COPY src /src

RUN mkdir /build && touch /build/.keepdir

WORKDIR /src

RUN if [ -f ./build.sh ]; then ./build.sh; fi

RUN touch .keepdir

