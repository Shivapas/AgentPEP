#!/usr/bin/env bash
# APEP-198: Air-gapped deployment — load bundled images into a private registry.
# Usage: ./load-images.sh --archive <tarball> --registry <registry-url>
#
# Loads images from the bundle tarball and re-tags/pushes them to a private
# registry for use in air-gapped Kubernetes clusters.

set -euo pipefail

ARCHIVE=""
REGISTRY=""

usage() {
  echo "Usage: $0 --archive <tarball> --registry <registry-url>"
  echo ""
  echo "Options:"
  echo "  --archive    Path to the image bundle tarball"
  echo "  --registry   Target private registry URL (e.g., registry.internal:5000)"
  exit 1
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --archive) ARCHIVE="$2"; shift 2 ;;
    --registry) REGISTRY="$2"; shift 2 ;;
    -h|--help) usage ;;
    *) echo "Unknown option: $1"; usage ;;
  esac
done

if [[ -z "${ARCHIVE}" || -z "${REGISTRY}" ]]; then
  echo "ERROR: --archive and --registry are required"
  usage
fi

if [[ ! -f "${ARCHIVE}" ]]; then
  echo "ERROR: Archive not found: ${ARCHIVE}"
  exit 1
fi

echo "[airgap] Loading images from ${ARCHIVE}..."
LOADED=$(gunzip -c "${ARCHIVE}" | docker load 2>&1)
echo "${LOADED}"

# Extract image names from the load output
IMAGES=$(echo "${LOADED}" | grep "Loaded image:" | sed 's/Loaded image: //')

echo ""
echo "[airgap] Re-tagging and pushing to ${REGISTRY}..."
PUSH_FAILURES=0
for img in ${IMAGES}; do
  # Build the new tag: registry/original-path
  NEW_TAG="${REGISTRY}/${img}"
  echo "  ${img} -> ${NEW_TAG}"
  docker tag "${img}" "${NEW_TAG}"
  if ! docker push "${NEW_TAG}"; then
    echo "  ERROR: Failed to push ${NEW_TAG}"
    PUSH_FAILURES=$((PUSH_FAILURES + 1))
  fi
done

if [[ ${PUSH_FAILURES} -gt 0 ]]; then
  echo ""
  echo "[airgap] WARNING: ${PUSH_FAILURES} image(s) failed to push"
  exit 1
fi

echo ""
echo "[airgap] All images pushed to ${REGISTRY}"
echo ""
echo "Update your Helm values to use the private registry:"
echo ""
echo "  helm install agentpep ./infra/helm/agentpep \\"
echo "    --set api.image.repository=${REGISTRY}/agentpep/agentpep-api \\"
echo "    --set console.image.repository=${REGISTRY}/agentpep/agentpep-console \\"
echo "    --set mongodb.image.repository=${REGISTRY}/mongo \\"
echo "    --set kafka.image.repository=${REGISTRY}/confluentinc/cp-kafka \\"
echo "    --set zookeeper.image.repository=${REGISTRY}/confluentinc/cp-zookeeper"
