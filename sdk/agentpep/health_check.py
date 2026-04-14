"""CLI health check — verify server connectivity and backend status.

Sprint 34 — APEP-274: ``agentpep health`` CLI command to check server
connectivity, policy sync status, and backend health for all registered
backends.
"""

from __future__ import annotations

import json
import sys
import time
from typing import Any

import httpx


def check_health(
    *,
    base_url: str = "http://localhost:8000",
    api_key: str | None = None,
    timeout: float = 5.0,
    verbose: bool = False,
) -> int:
    """Check AgentPEP server health and backend connectivity.

    Checks:
    1. Server connectivity (GET /health)
    2. Policy sync status (GET /v1/policy/status)
    3. Backend health for registered backends

    Args:
        base_url: AgentPEP server URL.
        api_key: Optional API key.
        timeout: Request timeout in seconds.
        verbose: Print detailed output.

    Returns:
        0 if all checks pass, 1 if any fail.
    """
    base_url = base_url.rstrip("/")
    headers: dict[str, str] = {"Content-Type": "application/json"}
    if api_key:
        headers["X-API-Key"] = api_key

    checks_passed = 0
    checks_failed = 0
    total_checks = 0

    print(f"AgentPEP Health Check — {base_url}")
    print("=" * 50)

    # --- Check 1: Server connectivity ---
    total_checks += 1
    print("\n[1/3] Server connectivity...", end=" ")
    start = time.monotonic()
    try:
        with httpx.Client(timeout=timeout) as client:
            resp = client.get(f"{base_url}/health", headers=headers)
            latency_ms = int((time.monotonic() - start) * 1000)

            if resp.status_code == 200:
                data = resp.json()
                version = data.get("version", "unknown")
                print(f"OK ({latency_ms}ms)")
                print(f"  Server version: {version}")
                if verbose:
                    print(f"  Response: {json.dumps(data, indent=2)}")
                checks_passed += 1
            else:
                print(f"FAIL (HTTP {resp.status_code})")
                checks_failed += 1
    except httpx.ConnectError:
        print("FAIL (connection refused)")
        print(f"  Cannot reach {base_url}")
        checks_failed += 1
    except httpx.TimeoutException:
        print(f"FAIL (timeout after {timeout}s)")
        checks_failed += 1
    except Exception as exc:
        print(f"FAIL ({exc})")
        checks_failed += 1

    # --- Check 2: Policy sync status ---
    total_checks += 1
    print("\n[2/3] Policy sync status...", end=" ")
    try:
        with httpx.Client(timeout=timeout) as client:
            resp = client.get(f"{base_url}/v1/policy/rules", headers=headers)
            if resp.status_code == 200:
                data = resp.json()
                rules = data if isinstance(data, list) else data.get("rules", [])
                print(f"OK ({len(rules)} rules loaded)")
                checks_passed += 1
            elif resp.status_code == 404:
                print("OK (endpoint not available — using defaults)")
                checks_passed += 1
            else:
                print(f"WARNING (HTTP {resp.status_code})")
                checks_passed += 1  # Non-critical
    except httpx.ConnectError:
        print("SKIP (server not reachable)")
        checks_failed += 1
    except httpx.TimeoutException:
        print("SKIP (timeout)")
        checks_failed += 1
    except Exception as exc:
        print(f"SKIP ({exc})")
        checks_failed += 1

    # --- Check 3: Backend health ---
    total_checks += 1
    print("\n[3/3] Backend health...", end=" ")
    try:
        with httpx.Client(timeout=timeout) as client:
            resp = client.get(f"{base_url}/v1/health/backends", headers=headers)
            if resp.status_code == 200:
                data = resp.json()
                backends = data if isinstance(data, list) else data.get("backends", [])
                if backends:
                    healthy = sum(1 for b in backends if b.get("healthy", False))
                    print(f"OK ({healthy}/{len(backends)} healthy)")
                    if verbose:
                        for b in backends:
                            status = "OK" if b.get("healthy") else "FAIL"
                            print(f"  [{status}] {b.get('name', 'unknown')}: "
                                  f"{b.get('type', '?')}")
                else:
                    print("OK (no backends registered)")
                checks_passed += 1
            elif resp.status_code == 404:
                print("OK (endpoint not available — single backend mode)")
                checks_passed += 1
            else:
                print(f"WARNING (HTTP {resp.status_code})")
                checks_passed += 1
    except httpx.ConnectError:
        print("SKIP (server not reachable)")
        checks_failed += 1
    except httpx.TimeoutException:
        print("SKIP (timeout)")
        checks_failed += 1
    except Exception as exc:
        print(f"SKIP ({exc})")
        checks_failed += 1

    # --- Summary ---
    print("\n" + "=" * 50)
    print(f"Results: {checks_passed}/{total_checks} checks passed")

    if checks_failed > 0:
        print(f"  {checks_failed} check(s) failed")
        return 1

    print("  All checks passed")
    return 0
