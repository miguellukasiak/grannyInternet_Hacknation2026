#!/bin/sh
# Proxy mode: a local SOCKS5 port, no TUN device; the registration stays in the volume, made once
warp-svc --accept-tos &
until warp-cli --accept-tos status >/dev/null 2>&1; do sleep 1; done
warp-cli --accept-tos registration show >/dev/null 2>&1 || warp-cli --accept-tos registration new
warp-cli --accept-tos mode proxy
warp-cli --accept-tos proxy port 40000
warp-cli --accept-tos connect
# warp-svc listens on 127.0.0.1 only: socat opens it to the Docker network (the port is never published)
exec socat TCP-LISTEN:1080,fork,reuseaddr TCP:127.0.0.1:40000
