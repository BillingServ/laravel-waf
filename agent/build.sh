#!/usr/bin/env sh
set -eu

agent_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
binary_name=${BINARY_NAME:-lwafd}
target_os=${GOOS:-linux}
target_arch=${GOARCH:-amd64}

case "$binary_name" in
    ''|*[!A-Za-z0-9._-]*)
        printf 'BINARY_NAME must contain only letters, numbers, dots, underscores, or hyphens.\n' >&2
        exit 1
        ;;
esac

mkdir -p "$agent_dir/bin"

cd "$agent_dir"
CGO_ENABLED=${CGO_ENABLED:-0} GOOS="$target_os" GOARCH="$target_arch" go build \
    -buildvcs=false \
    -trimpath \
    -ldflags "-s -w -buildid= -X main.programName=$binary_name" \
    -o "$agent_dir/bin/$binary_name" \
    ./cmd/lwafd

printf 'Built %s (%s/%s)\n' "$agent_dir/bin/$binary_name" "$target_os" "$target_arch"
