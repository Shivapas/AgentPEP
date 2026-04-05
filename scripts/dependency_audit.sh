#!/usr/bin/env bash
# APEP-194: Third-party dependency audit script
#
# Runs pip-audit on the Python backend/SDK and npm audit on the frontend.
# Exits with non-zero status if any CRITICAL or HIGH vulnerabilities are found.
#
# Usage:
#   ./scripts/dependency_audit.sh          # audit all components
#   ./scripts/dependency_audit.sh backend  # audit backend only
#   ./scripts/dependency_audit.sh frontend # audit frontend only
#   ./scripts/dependency_audit.sh sdk      # audit SDK only

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
EXIT_CODE=0
COMPONENT="${1:-all}"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Colour

log_info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*"; }

# ---------------------------------------------------------------------------
# Python: pip-audit
# ---------------------------------------------------------------------------
audit_python() {
    local name="$1"
    local dir="$2"

    log_info "Auditing $name Python dependencies..."

    if ! command -v pip-audit &>/dev/null; then
        log_warn "pip-audit not found. Installing..."
        pip install pip-audit --quiet
    fi

    pushd "$dir" > /dev/null

    if pip-audit --strict --desc --format columns 2>&1; then
        log_info "$name: No vulnerabilities found."
    else
        local audit_exit=$?
        if [ $audit_exit -ne 0 ]; then
            log_error "$name: Vulnerabilities detected (exit code $audit_exit)."
            EXIT_CODE=1
        fi
    fi

    popd > /dev/null
}

# ---------------------------------------------------------------------------
# Node.js: npm audit
# ---------------------------------------------------------------------------
audit_npm() {
    local name="$1"
    local dir="$2"

    log_info "Auditing $name npm dependencies..."

    if ! command -v npm &>/dev/null; then
        log_error "npm not found. Please install Node.js."
        EXIT_CODE=1
        return
    fi

    pushd "$dir" > /dev/null

    # npm audit exits non-zero on any vulnerability; we only fail on critical/high
    local audit_output
    audit_output=$(npm audit --json 2>/dev/null || true)

    local critical
    local high
    critical=$(echo "$audit_output" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    vulns = data.get('metadata', {}).get('vulnerabilities', {})
    print(vulns.get('critical', 0))
except Exception:
    print(0)
" 2>/dev/null || echo "0")

    high=$(echo "$audit_output" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    vulns = data.get('metadata', {}).get('vulnerabilities', {})
    print(vulns.get('high', 0))
except Exception:
    print(0)
" 2>/dev/null || echo "0")

    if [ "$critical" -gt 0 ] || [ "$high" -gt 0 ]; then
        log_error "$name: Found $critical critical and $high high vulnerabilities."
        npm audit 2>/dev/null || true
        EXIT_CODE=1
    else
        log_info "$name: No critical/high vulnerabilities found."
        npm audit 2>/dev/null || true
    fi

    popd > /dev/null
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

log_info "AgentPEP Dependency Audit (APEP-194)"
log_info "======================================"

if [ "$COMPONENT" = "all" ] || [ "$COMPONENT" = "backend" ]; then
    audit_python "Backend" "$REPO_ROOT/backend"
fi

if [ "$COMPONENT" = "all" ] || [ "$COMPONENT" = "sdk" ]; then
    audit_python "SDK" "$REPO_ROOT/sdk"
fi

if [ "$COMPONENT" = "all" ] || [ "$COMPONENT" = "frontend" ]; then
    audit_npm "Frontend" "$REPO_ROOT/frontend"
fi

echo ""
if [ $EXIT_CODE -eq 0 ]; then
    log_info "All dependency audits passed."
else
    log_error "Dependency audit found critical/high vulnerabilities. Please remediate."
fi

exit $EXIT_CODE
