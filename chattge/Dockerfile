FROM --platform=i386 debian:bullseye-slim as base

RUN apt-get update \
    && apt-get install -y --no-install-recommends wget ca-certificates
RUN mkdir -pm755 /etc/apt/keyrings \
    && wget -O /etc/apt/keyrings/winehq-archive.key https://dl.winehq.org/wine-builds/winehq.key \
    && wget -NP /etc/apt/sources.list.d/ https://dl.winehq.org/wine-builds/debian/dists/bullseye/winehq-bullseye.sources
RUN dpkg --add-architecture i386 \
    && apt-get update \
    && apt-get install -y --no-install-recommends winehq-stable xvfb xauth \
    && rm -rf /var/lib/apt/lists/*
RUN apt-get update \
    && apt-get install -y --no-install-recommends netcat python3 \
    && rm -rf /var/lib/apt/lists/*

FROM base as build

COPY chal /chal

WORKDIR /chal
RUN chmod +x /chal/build.sh
RUN /chal/build.sh

# ----------------------------------------------------------
FROM base as run

COPY --from=build /server.tar.gz /server.tar.gz
COPY --from=build /handout.tar.gz /handout.tar.gz

RUN mkdir /chal
WORKDIR /chal
RUN tar xvzf /server.tar.gz

# Or change to whatever you want
RUN echo "flag{shoutouts_to_maccarbstrings_cc_how_did_that_ever_ship}" > /chal/flag.txt

EXPOSE 28080

ENTRYPOINT [ "/bin/bash", "/chal/start.sh" ]
