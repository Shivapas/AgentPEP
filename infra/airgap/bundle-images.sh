#!/usr/bin/env bash
# APEP-198: Air-gapped deployment — bundle all container images into a tarball.
# Usage: ./bundle-images.sh [--output <path>] [--values <values.yaml>]
#
# Pulls all images referenced by the Helm chart, saves them as a single
# OCI-compatible tarball that can be transferred to an air-gapped registry.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CHART_DIR="${SCRIPT_DIR}/../helm/agentpep"
OUTPUT="agentpep-images-bundle.tar.gz"
VALUES_FILE=""

usage() {
  echo "Usage: $0 [--output <path>] [--values <values.yaml>]"
  echo ""
  echo "Options:"
  echo "  --output    Output tarball path (default: agentpep-images-bundle.tar.gz)"
  echo "  --values    Custom values file to extract image refs from"
  exit 1
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --output) OUTPUT="$2"; shift 2 ;;
    --values) VALUES_FILE="$2"; shift 2 ;;
    -h|--help) usage ;;
    *) echo "Unknown option: $1"; usage ;;
  esac
done

# Default images from chart values
IMAGES=(
  "agentpep/agentpep-api:0.1.0"
  "agentpep/agentpep-console:0.1.0"
  "mongo:7.0.14"
  "confluentinc/cp-kafka:7.7.0"
  "confluentinc/cp-zookeeper:7.7.0"
  "busybox:1.36.1"
)

# If a custom values file is provided, parse image overrides
if [[ -n "${VALUES_FILE}" ]]; then
  echo "[airgap] Parsing image references from ${VALUES_FILE}"
  if command -v yq &>/dev/null; then
    API_IMG=$(yq '.api.image.repository + ":" + .api.image.tag' "${VALUES_FILE}" 2>/dev/null || true)
    CONSOLE_IMG=$(yq '.console.image.repository + ":" + .console.image.tag' "${VALUES_FILE}" 2>/dev/null || true)
    MONGO_IMG=$(yq '.mongodb.image.repository + ":" + .mongodb.image.tag' "${VALUES_FILE}" 2>/dev/null || true)
    KAFKA_IMG=$(yq '.kafka.image.repository + ":" + .kafka.image.tag' "${VALUES_FILE}" 2>/dev/null || true)
    ZK_IMG=$(yq '.zookeeper.image.repository + ":" + .zookeeper.image.tag' "${VALUES_FILE}" 2>/dev/null || true)

    IMAGES=()
    [[ -n "${API_IMG}" && "${API_IMG}" != "null:null" ]] && IMAGES+=("${API_IMG}")
    [[ -n "${CONSOLE_IMG}" && "${CONSOLE_IMG}" != "null:null" ]] && IMAGES+=("${CONSOLE_IMG}")
    [[ -n "${MONGO_IMG}" && "${MONGO_IMG}" != "null:null" ]] && IMAGES+=("${MONGO_IMG}")
    [[ -n "${KAFKA_IMG}" && "${KAFKA_IMG}" != "null:null" ]] && IMAGES+=("${KAFKA_IMG}")
    [[ -n "${ZK_IMG}" && "${ZK_IMG}" != "null:null" ]] && IMAGES+=("${ZK_IMG}")
    IMAGES+=("busybox:1.36.1")
  else
    echo "[airgap] WARNING: yq not found, using default image references"
  fi
fi

echo "[airgap] Bundling ${#IMAGES[@]} images:"
for img in "${IMAGES[@]}"; do
  echo "  - ${img}"
done

# Pull all images
echo ""
echo "[airgap] Pulling images..."
for img in "${IMAGES[@]}"; do
  echo "  Pulling ${img}..."
  docker pull "${img}"
done

# Save all images into a single tarball
echo ""
echo "[airgap] Saving images to ${OUTPUT}..."
docker save "${IMAGES[@]}" | gzip > "${OUTPUT}"

SIZE=$(du -h "${OUTPUT}" | cut -f1)
echo "[airgap] Bundle created: ${OUTPUT} (${SIZE})"
echo ""
echo "To load on an air-gapped host:"
echo "  gunzip -c ${OUTPUT} | docker load"
echo ""
echo "To push to a private registry:"
echo "  ./load-images.sh --archive ${OUTPUT} --registry <your-registry>"
