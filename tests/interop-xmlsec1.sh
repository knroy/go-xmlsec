#!/bin/sh
# Runs the xmlsec1 differential in a container, for machines without xmlsec1
# 1.3 on the PATH. Alpine is used because it ships xmlsec 1.3: 1.2.x, still
# what Debian and Ubuntu package, does not implement the XML Encryption 1.1
# rsa-oaep algorithm at all. Extra arguments are
# passed to go test, e.g. -run TestWeVerify.
set -eu
cd "$(dirname "$0")/.."
docker build -q -t go-xmlsec-xmlsec1 - >/dev/null <<'EOF'
FROM golang:1.26-alpine
RUN apk add --no-cache xmlsec
EOF
exec docker run --rm -v "$PWD":/src -w /src -v go-xmlsec-modcache:/go/pkg/mod \
	-e GOXMLSEC_REQUIRE_XMLSEC1=1 go-xmlsec-xmlsec1 \
	go test -tags interop -count=1 -v ./tests/interop "$@"
