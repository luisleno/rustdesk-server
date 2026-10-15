# FvConnect server image: same binaries as docker-classic, but with CA certificates so hbbs
# can call the portal over https (license gate).
FROM alpine:3.20
RUN apk add --no-cache ca-certificates tzdata
COPY hbbs /usr/bin/hbbs
COPY hbbr /usr/bin/hbbr
WORKDIR /root
ENV HOME=/root
