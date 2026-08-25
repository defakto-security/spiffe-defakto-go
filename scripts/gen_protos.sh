#!/usr/bin/env bash
# Regenerate Go bindings from the vendored .proto files.
#
# Run from the repo root: ./scripts/gen_protos.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/attestingworkloadapi/internal/serverlessapi"

go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.36.12
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.6.2
export PATH="$(go env GOPATH)/bin:$PATH"

mkdir -p "$OUT"

protoc \
    --proto_path="$ROOT/protos/alpha/serverlessapi" \
    --go_out="$OUT" --go_opt=paths=source_relative \
    --go-grpc_out="$OUT" --go-grpc_opt=paths=source_relative \
    "$ROOT/protos/alpha/serverlessapi/api.proto"

echo "proto generation complete"
