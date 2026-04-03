#!/usr/bin/env bash
# APEP-199: Installation validation script.
# Checks that all AgentPEP services are healthy after a Helm install.
#
# Usage: ./validate-install.sh [--namespace <ns>] [--release <name>] [--timeout <seconds>]

set -euo pipefail

NAMESPACE="default"
RELEASE="agentpep"
TIMEOUT=300
PASSED=0
FAILED=0
WARNINGS=0

usage() {
  echo "Usage: $0 [--namespace <ns>] [--release <name>] [--timeout <seconds>]"
  exit 1
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --namespace|-n) NAMESPACE="$2"; shift 2 ;;
    --release|-r) RELEASE="$2"; shift 2 ;;
    --timeout|-t) TIMEOUT="$2"; shift 2 ;;
    -h|--help) usage ;;
    *) echo "Unknown option: $1"; usage ;;
  esac
done

KUBECTL="kubectl -n ${NAMESPACE}"

log_pass() { echo "  [PASS] $1"; PASSED=$((PASSED + 1)); }
log_fail() { echo "  [FAIL] $1"; FAILED=$((FAILED + 1)); }
log_warn() { echo "  [WARN] $1"; WARNINGS=$((WARNINGS + 1)); }
log_info() { echo "  [INFO] $1"; }

echo "=============================================="
echo " AgentPEP Installation Validation"
echo "=============================================="
echo " Namespace: ${NAMESPACE}"
echo " Release:   ${RELEASE}"
echo " Timeout:   ${TIMEOUT}s"
echo "=============================================="
echo ""

# --- Check 1: Helm release status ---
echo "[1/7] Checking Helm release status..."
HELM_STATUS=$(helm status "${RELEASE}" -n "${NAMESPACE}" -o json 2>/dev/null | grep -o '"status":"[^"]*"' | head -1 || true)
if echo "${HELM_STATUS}" | grep -q "deployed"; then
  log_pass "Helm release '${RELEASE}' is deployed"
else
  log_fail "Helm release '${RELEASE}' not found or not deployed"
fi

# --- Check 2: API pods ---
echo ""
echo "[2/7] Checking API pods..."
API_READY=$(${KUBECTL} get pods -l "app.kubernetes.io/component=api,app.kubernetes.io/instance=${RELEASE}" \
  -o jsonpath='{.items[*].status.conditions[?(@.type=="Ready")].status}' 2>/dev/null || true)
API_COUNT=$(echo "${API_READY}" | wc -w)

if [[ ${API_COUNT} -gt 0 ]]; then
  ALL_READY=true
  for status in ${API_READY}; do
    [[ "${status}" != "True" ]] && ALL_READY=false
  done
  if ${ALL_READY}; then
    log_pass "API: ${API_COUNT} pod(s) ready"
  else
    log_fail "API: some pods not ready"
  fi
else
  log_fail "API: no pods found"
fi

# --- Check 3: Console pods ---
echo ""
echo "[3/7] Checking Console pods..."
CONSOLE_READY=$(${KUBECTL} get pods -l "app.kubernetes.io/component=console,app.kubernetes.io/instance=${RELEASE}" \
  -o jsonpath='{.items[*].status.conditions[?(@.type=="Ready")].status}' 2>/dev/null || true)
CONSOLE_COUNT=$(echo "${CONSOLE_READY}" | wc -w)

if [[ ${CONSOLE_COUNT} -gt 0 ]]; then
  ALL_READY=true
  for status in ${CONSOLE_READY}; do
    [[ "${status}" != "True" ]] && ALL_READY=false
  done
  if ${ALL_READY}; then
    log_pass "Console: ${CONSOLE_COUNT} pod(s) ready"
  else
    log_fail "Console: some pods not ready"
  fi
elif [[ ${CONSOLE_COUNT} -eq 0 ]]; then
  log_warn "Console: no pods found (may be disabled)"
fi

# --- Check 4: MongoDB pods ---
echo ""
echo "[4/7] Checking MongoDB pods..."
MONGO_READY=$(${KUBECTL} get pods -l "app.kubernetes.io/component=mongodb,app.kubernetes.io/instance=${RELEASE}" \
  -o jsonpath='{.items[*].status.conditions[?(@.type=="Ready")].status}' 2>/dev/null || true)
MONGO_COUNT=$(echo "${MONGO_READY}" | wc -w)

if [[ ${MONGO_COUNT} -gt 0 ]]; then
  ALL_READY=true
  for status in ${MONGO_READY}; do
    [[ "${status}" != "True" ]] && ALL_READY=false
  done
  if ${ALL_READY}; then
    log_pass "MongoDB: ${MONGO_COUNT} pod(s) ready"
  else
    log_fail "MongoDB: some pods not ready"
  fi
else
  log_warn "MongoDB: no pods found (may use external instance)"
fi

# --- Check 5: Kafka pods ---
echo ""
echo "[5/7] Checking Kafka & Zookeeper pods..."
KAFKA_READY=$(${KUBECTL} get pods -l "app.kubernetes.io/component=kafka,app.kubernetes.io/instance=${RELEASE}" \
  -o jsonpath='{.items[*].status.conditions[?(@.type=="Ready")].status}' 2>/dev/null || true)
ZK_READY=$(${KUBECTL} get pods -l "app.kubernetes.io/component=zookeeper,app.kubernetes.io/instance=${RELEASE}" \
  -o jsonpath='{.items[*].status.conditions[?(@.type=="Ready")].status}' 2>/dev/null || true)

KAFKA_COUNT=$(echo "${KAFKA_READY}" | wc -w)
ZK_COUNT=$(echo "${ZK_READY}" | wc -w)

if [[ ${KAFKA_COUNT} -gt 0 ]]; then
  log_pass "Kafka: ${KAFKA_COUNT} pod(s) found"
else
  log_warn "Kafka: no pods found (may be disabled)"
fi
if [[ ${ZK_COUNT} -gt 0 ]]; then
  log_pass "Zookeeper: ${ZK_COUNT} pod(s) found"
else
  log_warn "Zookeeper: no pods found (may be disabled)"
fi

# --- Check 6: API health endpoint ---
echo ""
echo "[6/7] Checking API health endpoint..."
API_POD=$(${KUBECTL} get pods -l "app.kubernetes.io/component=api,app.kubernetes.io/instance=${RELEASE}" \
  -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)

if [[ -n "${API_POD}" ]]; then
  HEALTH=$(${KUBECTL} exec "${API_POD}" -- wget -qO- http://localhost:8000/v1/health 2>/dev/null || true)
  if echo "${HEALTH}" | grep -qi "healthy\|ok\|status"; then
    log_pass "API health endpoint responding"
  else
    log_fail "API health endpoint not responding"
  fi
else
  log_fail "Cannot check health — no API pod available"
fi

# --- Check 7: PersistentVolumeClaims ---
echo ""
echo "[7/7] Checking PersistentVolumeClaims..."
PVC_STATUS=$(${KUBECTL} get pvc -l "app.kubernetes.io/instance=${RELEASE}" \
  -o jsonpath='{range .items[*]}{.metadata.name}={.status.phase}{" "}{end}' 2>/dev/null || true)

if [[ -n "${PVC_STATUS}" ]]; then
  ALL_BOUND=true
  for pvc in ${PVC_STATUS}; do
    NAME=$(echo "${pvc}" | cut -d= -f1)
    PHASE=$(echo "${pvc}" | cut -d= -f2)
    if [[ "${PHASE}" == "Bound" ]]; then
      log_pass "PVC ${NAME}: Bound"
    else
      log_fail "PVC ${NAME}: ${PHASE}"
      ALL_BOUND=false
    fi
  done
else
  log_info "No PVCs found (persistence may be disabled)"
fi

# --- Summary ---
echo ""
echo "=============================================="
echo " Validation Summary"
echo "=============================================="
echo "  Passed:   ${PASSED}"
echo "  Failed:   ${FAILED}"
echo "  Warnings: ${WARNINGS}"
echo "=============================================="

if [[ ${FAILED} -gt 0 ]]; then
  echo ""
  echo "RESULT: FAILED — ${FAILED} check(s) did not pass."
  exit 1
else
  echo ""
  echo "RESULT: PASSED — All checks passed."
  exit 0
fi
