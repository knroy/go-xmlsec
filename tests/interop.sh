#!/bin/sh
# Runs the interop differential against xmlsec1 1.3 and Apache Santuario,
# in the container tests/Dockerfile builds. CI runs this same script.
# Extra arguments are passed to go test, e.g. -run Santuario.
set -eu
cd "$(dirname "$0")/.."
docker build -q -t go-xmlsec-interop -f tests/Dockerfile tests >/dev/null
exec docker run --rm -v "$PWD":/src -w /src -v go-xmlsec-modcache:/go/pkg/mod \
	-e GOXMLSEC_REQUIRE_INTEROP=1 go-xmlsec-interop \
	go test -tags interop -count=1 -v ./tests/interop "$@"
