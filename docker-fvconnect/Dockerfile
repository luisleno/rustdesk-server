# FvConnect server image: hbbs/hbbr (glibc build) with CA certificates and OpenSSL,
# so hbbs can call the portal over https (license gate).
FROM debian:bookworm-slim
RUN apt-get update     && apt-get install -y --no-install-recommends ca-certificates libssl3 tzdata     && rm -rf /var/lib/apt/lists/*
COPY hbbs /usr/bin/hbbs
COPY hbbr /usr/bin/hbbr
WORKDIR /root
ENV HOME=/root
