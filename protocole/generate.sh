#!/bin/sh
set -eu

PROTOC_VERSION='3.21.12'
PROTOC_GEN_GO_VERSION='v1.36.6'

actual=$(protoc --version | awk '{print $2}')
if [ "$actual" != "$PROTOC_VERSION" ]; then
  echo "protoc $PROTOC_VERSION requis, trouvé : $actual" >&2
  exit 1
fi

actual_go=$(protoc-gen-go --version | awk '{print $2}')
if [ "$actual_go" != "$PROTOC_GEN_GO_VERSION" ]; then
  echo "protoc-gen-go $PROTOC_GEN_GO_VERSION requis, trouvé : $actual_go" >&2
  exit 1
fi

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
mkdir -p "$root/protocole/gen/go" "$root/console/src/your_cloud_console/protocol"

protoc \
  --proto_path="$root/protocole/v1" \
  --go_out="$root/protocole/gen/go" \
  --go_opt=paths=source_relative \
  --python_out="$root/console/src/your_cloud_console/protocol" \
  "$root/protocole/v1/telemetrie.proto"
