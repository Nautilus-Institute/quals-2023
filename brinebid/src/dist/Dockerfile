# Example deployment only
# Production server's environment may differ slightly
FROM denoland/deno:debian-1.33.3

WORKDIR /opt

RUN echo 'flug{flag will be here and you know the drill by now...}' > /opt/flag.txt

ADD main.bundle.js /opt/main.bundle.js

USER deno
CMD ["deno", "run", "--allow-net", "--allow-read", "--allow-write", "/opt/main.bundle.js"]

