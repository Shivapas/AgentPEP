/**
 * k6 Load Test — AgentPEP Intercept API (APEP-185)
 *
 * Target: 5,000 RPS sustained for 2 minutes with ramp-up/down.
 * Captures p50, p95, p99 latency metrics.
 *
 * Run:
 *   k6 run loadtests/k6_intercept.js
 *
 * Environment variables:
 *   BASE_URL  — AgentPEP backend URL (default: http://localhost:8000)
 */

import http from "k6/http";
import { check, sleep } from "k6";
import { Rate, Trend } from "k6/metrics";

// Custom metrics
const interceptLatency = new Trend("intercept_latency_ms", true);
const interceptErrors = new Rate("intercept_errors");

// Test configuration
const BASE_URL = __ENV.BASE_URL || "http://localhost:8000";

export const options = {
  stages: [
    { duration: "30s", target: 500 },    // Ramp up to 500 VUs
    { duration: "30s", target: 2000 },   // Ramp up to 2000 VUs
    { duration: "30s", target: 5000 },   // Ramp up to 5000 VUs
    { duration: "2m", target: 5000 },    // Sustain 5000 VUs
    { duration: "30s", target: 0 },      // Ramp down
  ],
  thresholds: {
    // p99 cached < 15ms, p99 cold < 50ms
    intercept_latency_ms: [
      "p(50)<10",
      "p(95)<25",
      "p(99)<50",
    ],
    intercept_errors: ["rate<0.01"],  // < 1% error rate
    http_req_duration: [
      "p(50)<10",
      "p(95)<25",
      "p(99)<50",
    ],
  },
};

// Pre-built request payloads to avoid runtime serialisation overhead
const PAYLOADS = [
  {
    session_id: "load-test-session-1",
    agent_id: "agent-loadtest-1",
    tool_name: "file.read",
    tool_args: { path: "/tmp/test.txt" },
  },
  {
    session_id: "load-test-session-2",
    agent_id: "agent-loadtest-2",
    tool_name: "http.get",
    tool_args: { url: "https://example.com/api" },
  },
  {
    session_id: "load-test-session-3",
    agent_id: "agent-loadtest-3",
    tool_name: "db.query",
    tool_args: { query: "SELECT 1" },
  },
  {
    session_id: "load-test-session-4",
    agent_id: "agent-loadtest-1",
    tool_name: "shell.exec",
    tool_args: { command: "echo hello" },
  },
  {
    session_id: "load-test-session-5",
    agent_id: "agent-loadtest-2",
    tool_name: "file.write",
    tool_args: { path: "/tmp/out.txt", content: "data" },
  },
];

const PAYLOAD_STRINGS = PAYLOADS.map((p) => JSON.stringify(p));

const HEADERS = {
  "Content-Type": "application/json",
};

export default function () {
  // Round-robin through payloads
  const idx = __ITER % PAYLOAD_STRINGS.length;
  const payload = PAYLOAD_STRINGS[idx];

  const res = http.post(`${BASE_URL}/v1/intercept`, payload, {
    headers: HEADERS,
    timeout: "5s",
  });

  // Record custom latency metric
  interceptLatency.add(res.timings.duration);

  // Check response
  const success = check(res, {
    "status is 200": (r) => r.status === 200,
    "has decision field": (r) => {
      try {
        const body = JSON.parse(r.body);
        return body.decision !== undefined;
      } catch {
        return false;
      }
    },
  });

  if (!success) {
    interceptErrors.add(1);
  } else {
    interceptErrors.add(0);
  }
}

export function handleSummary(data) {
  const metrics = data.metrics;

  const summary = {
    timestamp: new Date().toISOString(),
    test: "APEP-185: Intercept API Load Test",
    target_rps: 5000,
    results: {
      total_requests: metrics.http_reqs ? metrics.http_reqs.values.count : 0,
      rps: metrics.http_reqs ? metrics.http_reqs.values.rate : 0,
      latency: {
        p50_ms: metrics.intercept_latency_ms
          ? metrics.intercept_latency_ms.values["p(50)"]
          : null,
        p95_ms: metrics.intercept_latency_ms
          ? metrics.intercept_latency_ms.values["p(95)"]
          : null,
        p99_ms: metrics.intercept_latency_ms
          ? metrics.intercept_latency_ms.values["p(99)"]
          : null,
        avg_ms: metrics.intercept_latency_ms
          ? metrics.intercept_latency_ms.values.avg
          : null,
        max_ms: metrics.intercept_latency_ms
          ? metrics.intercept_latency_ms.values.max
          : null,
      },
      error_rate: metrics.intercept_errors
        ? metrics.intercept_errors.values.rate
        : null,
    },
    thresholds_passed: !Object.values(data.root_group.checks || {}).some(
      (c) => c.fails > 0
    ),
  };

  return {
    stdout: JSON.stringify(summary, null, 2) + "\n",
    "loadtests/results.json": JSON.stringify(summary, null, 2),
  };
}
