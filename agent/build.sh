#!/usr/bin/env sh
set -eu

agent_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
binary_name=${BINARY_NAME:-lwafd}
target_os=${GOOS:-linux}
target_arch=${GOARCH:-amd64}
agent_version=${LWAFD_VERSION:-}

if [ -z "$agent_version" ] && command -v git >/dev/null 2>&1; then
    agent_version=$(git -C "$agent_dir" describe --tags --always --dirty 2>/dev/null || true)
fi
agent_version=${agent_version:-unknown}

case "$binary_name" in
    ''|*[!A-Za-z0-9._-]*)
        printf 'BINARY_NAME must contain only letters, numbers, dots, underscores, or hyphens.\n' >&2
        exit 1
        ;;
esac

case "$agent_version" in
    ''|*[!A-Za-z0-9._+-]*)
        printf 'LWAFD_VERSION must contain only letters, numbers, dots, underscores, plus signs, or hyphens.\n' >&2
        exit 1
        ;;
esac

mkdir -p "$agent_dir/bin"

cd "$agent_dir"
CGO_ENABLED=${CGO_ENABLED:-0} GOOS="$target_os" GOARCH="$target_arch" go build \
    -buildvcs=false \
    -trimpath \
    -ldflags "-s -w -buildid= -X main.programName=$binary_name -X main.programVersion=$agent_version" \
    -o "$agent_dir/bin/$binary_name" \
    ./cmd/lwafd

printf 'Built %s (%s/%s, version %s)\n' "$agent_dir/bin/$binary_name" "$target_os" "$target_arch" "$agent_version"
