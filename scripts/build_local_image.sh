#!/usr/bin/env bash
set -euo pipefail

IMAGE_NAME="nse-ovs-vpn"
IMAGE_TAG="${IMAGE_TAG:-20260403-vpn-closeout}"
IMPORT_IMAGE="true"
OUTPUT_TAR=""
GO_BUILD_IMAGE="${GO_BUILD_IMAGE:-golang:1.24.10}"
GOPROXY_CACHE_DIR="${GOPROXY_CACHE_DIR:-/root/go/pkg/mod/cache/download}"
GOMODCACHE_DIR="${GOMODCACHE_DIR:-/tmp/nse-ovs-vpn-modcache}"
GOCACHE_DIR="${GOCACHE_DIR:-/tmp/nse-ovs-vpn-go-build}"
BINARY_NAME="nse-ovs-vpn"

usage() {
  cat <<'USAGE'
Usage: ./scripts/build_local_image.sh [--tag <tag>] [--import|--no-import] [--output-tar <path>]

Build the local VPN image and optionally import it into containerd.
The binary is compiled first with a local Go 1.24 container and host-side module caches,
then packaged with Dockerfile.prebuilt.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --tag)
      IMAGE_TAG="${2:-}"
      shift 2
      ;;
    --import)
      IMPORT_IMAGE="true"
      shift
      ;;
    --no-import)
      IMPORT_IMAGE="false"
      shift
      ;;
    --output-tar)
      OUTPUT_TAR="${2:-}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/.." && pwd)"
image_ref="${IMAGE_NAME}:${IMAGE_TAG}"
binary_path="${repo_root}/${BINARY_NAME}"
tar_path=""

cleanup() {
  if [[ -f "${binary_path}" ]]; then
    rm -f "${binary_path}"
  fi
  if [[ -z "${OUTPUT_TAR}" && -n "${tar_path}" && -f "${tar_path}" ]]; then
    rm -f "${tar_path}"
  fi
}

trap cleanup EXIT

mkdir -p "${GOMODCACHE_DIR}" "${GOCACHE_DIR}"

docker run --rm \
  -e GOMODCACHE=/gomodcache \
  -e GOCACHE=/gocache \
  -e GOPROXY=file:///gomodproxy,direct \
  -e GOSUMDB=off \
  -e GOTOOLCHAIN=local \
  -v "${repo_root}:/src" \
  -v "${GOPROXY_CACHE_DIR}:/gomodproxy:ro" \
  -v "${GOMODCACHE_DIR}:/gomodcache" \
  -v "${GOCACHE_DIR}:/gocache" \
  -w /src \
  "${GO_BUILD_IMAGE}" \
  sh -eu -c "go build -o /src/${BINARY_NAME} ."

build_cmd=(docker build -f "${repo_root}/Dockerfile.prebuilt" -t "${image_ref}")
for proxy_var in HTTP_PROXY HTTPS_PROXY NO_PROXY http_proxy https_proxy no_proxy; do
  if [[ -n "${!proxy_var:-}" ]]; then
    build_cmd+=(--build-arg "${proxy_var}=${!proxy_var}")
  fi
done
build_cmd+=("${repo_root}")

"${build_cmd[@]}"

tar_path="${OUTPUT_TAR}"
if [[ -z "${tar_path}" && "${IMPORT_IMAGE}" == "true" ]]; then
  tar_path="$(mktemp "/tmp/${IMAGE_NAME}-${IMAGE_TAG}.XXXXXX.tar")"
fi

if [[ -n "${tar_path}" ]]; then
  docker save "${image_ref}" -o "${tar_path}"
fi

if [[ "${IMPORT_IMAGE}" == "true" ]]; then
  ctr -n k8s.io images import "${tar_path}"
fi

echo "built ${image_ref}"
