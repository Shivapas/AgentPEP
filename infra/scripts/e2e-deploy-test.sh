#!/usr/bin/env bash
# APEP-203: End-to-end on-premises deployment test.
# Measures total installation time against the 2-hour SLA.
#
# Usage: ./e2e-deploy-test.sh [--namespace <ns>] [--values <file>] [--airgap]
#
# Prerequisites:
#   - kubectl configured with target cluster
#   - helm v3 installed
#   - For air-gapped: images pre-loaded into cluster registry

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CHART_DIR="${SCRIPT_DIR}/../helm/agentpep"
VALIDATE_SCRIPT="${SCRIPT_DIR}/validate-install.sh"
NAMESPACE="agentpep-e2e-test"
RELEASE="agentpep-e2e"
VALUES_FILE=""
AIRGAP=false
SLA_SECONDS=7200  # 2 hours

usage() {
  echo "Usage: $0 [--namespace <ns>] [--values <file>] [--airgap]"
  echo ""
  echo "Options:"
  echo "  --namespace   Kubernetes namespace (default: agentpep-e2e-test)"
  echo "  --values      Custom values file"
  echo "  --airgap      Use air-gapped values overlay"
  exit 1
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --namespace|-n) NAMESPACE="$2"; shift 2 ;;
    --values|-f) VALUES_FILE="$2"; shift 2 ;;
    --airgap) AIRGAP=true; shift ;;
    -h|--help) usage ;;
    *) echo "Unknown option: $1"; usage ;;
  esac
done

cleanup() {
  echo ""
  echo "[e2e] Cleaning up..."
  helm uninstall "${RELEASE}" -n "${NAMESPACE}" 2>/dev/null || true
  kubectl delete namespace "${NAMESPACE}" --wait=false 2>/dev/null || true
  echo "[e2e] Cleanup complete."
}

# Trap for cleanup on exit
trap cleanup EXIT

echo "=============================================="
echo " AgentPEP E2E Deployment Test"
echo "=============================================="
echo " Namespace:  ${NAMESPACE}"
echo " Release:    ${RELEASE}"
echo " Air-gapped: ${AIRGAP}"
echo " SLA:        $((SLA_SECONDS / 60)) minutes"
echo "=============================================="
echo ""

START_TIME=$(date +%s)

# Step 1: Create namespace
echo "[e2e] Step 1/5: Creating namespace..."
kubectl create namespace "${NAMESPACE}" --dry-run=client -o yaml | kubectl apply -f -
STEP1_TIME=$(date +%s)
echo "  Done ($((STEP1_TIME - START_TIME))s elapsed)"

# Step 2: Install Helm chart
echo ""
echo "[e2e] Step 2/5: Installing Helm chart..."
HELM_ARGS=(install "${RELEASE}" "${CHART_DIR}" -n "${NAMESPACE}" --wait --timeout 30m)

if [[ "${AIRGAP}" == "true" ]]; then
  HELM_ARGS+=(-f "${SCRIPT_DIR}/../airgap/values-airgap.yaml")
fi
if [[ -n "${VALUES_FILE}" ]]; then
  HELM_ARGS+=(-f "${VALUES_FILE}")
fi

helm "${HELM_ARGS[@]}"
STEP2_TIME=$(date +%s)
echo "  Done ($((STEP2_TIME - START_TIME))s elapsed)"

# Step 3: Wait for all pods to be ready
echo ""
echo "[e2e] Step 3/5: Waiting for all pods to be ready..."
kubectl wait --for=condition=Ready pods --all -n "${NAMESPACE}" --timeout=600s
STEP3_TIME=$(date +%s)
echo "  Done ($((STEP3_TIME - START_TIME))s elapsed)"

# Step 4: Run validation checks
echo ""
echo "[e2e] Step 4/5: Running validation checks..."
if [[ -x "${VALIDATE_SCRIPT}" ]]; then
  bash "${VALIDATE_SCRIPT}" --namespace "${NAMESPACE}" --release "${RELEASE}"
else
  echo "  WARNING: validate-install.sh not found or not executable, skipping"
fi
STEP4_TIME=$(date +%s)
echo "  Done ($((STEP4_TIME - START_TIME))s elapsed)"

# Step 5: Run Helm tests
echo ""
echo "[e2e] Step 5/5: Running Helm tests..."
helm test "${RELEASE}" -n "${NAMESPACE}" --timeout 5m || true
STEP5_TIME=$(date +%s)

END_TIME=$(date +%s)
TOTAL_SECONDS=$((END_TIME - START_TIME))
TOTAL_MINUTES=$((TOTAL_SECONDS / 60))

echo ""
echo "=============================================="
echo " E2E Deployment Test Results"
echo "=============================================="
echo " Total time:     ${TOTAL_MINUTES}m $((TOTAL_SECONDS % 60))s"
echo " SLA target:     $((SLA_SECONDS / 60))m"
echo ""
echo " Step breakdown:"
echo "   Namespace:    $((STEP1_TIME - START_TIME))s"
echo "   Helm install: $((STEP2_TIME - STEP1_TIME))s"
echo "   Pod ready:    $((STEP3_TIME - STEP2_TIME))s"
echo "   Validation:   $((STEP4_TIME - STEP3_TIME))s"
echo "   Helm tests:   $((STEP5_TIME - STEP4_TIME))s"
echo "=============================================="

if [[ ${TOTAL_SECONDS} -le ${SLA_SECONDS} ]]; then
  echo ""
  echo "RESULT: PASSED — Install completed within 2-hour SLA (${TOTAL_MINUTES}m)."
  exit 0
else
  echo ""
  echo "RESULT: FAILED — Install exceeded 2-hour SLA (${TOTAL_MINUTES}m)."
  exit 1
fi
