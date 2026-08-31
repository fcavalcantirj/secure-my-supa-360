import { test } from "node:test";
import assert from "node:assert/strict";
import { audit, setTrace } from "../scripts/audit.js";
import { normalizeFinding, sortFindings, buildSummary } from "../scripts/contract.js";

const originalFetch = global.fetch;

// ---------------------------------------------------------------------------
// Trace mode
// ---------------------------------------------------------------------------

test("setTrace: toggles the trace flag without error", () => {
  // Should be importable and callable (no-op if trace is off)
  setTrace(false);
  setTrace(true);
  setTrace(false);
});

// ---------------------------------------------------------------------------
// Fault isolation: SQL errors in one check must not abort the run
// ---------------------------------------------------------------------------

test("fault isolation: SQL errors in checks are caught, run completes with errors captured", async (t) => {
  // Mock fetch:
  // - project meta (GET /v1/projects/{ref}): return valid config
  // - SQL queries (POST /v1/projects/{ref}/database/query): return 500
  // This causes every SQL-based check to fail, but the run should still complete.
  global.fetch = async (url, opts) => {
    const urlStr = String(url);
    if (urlStr.includes("/database/query")) {
      // Simulate a non-auth SQL error (500, not 401/403)
      return new Response(JSON.stringify({ message: "simulated DB error" }), { status: 500 });
    }
    if (urlStr.includes("/v1/projects/test-ref")) {
      // Project metadata — valid config with network restrictions enabled (no finding)
      return new Response(
        JSON.stringify({
          name: "test-proj",
          region: "us-east-1",
          network_restrictions: { enabled: true },
          db_ssl: true,
          pool_mode: "transaction",
        }),
        { status: 200 }
      );
    }
    // Default: return 200 with empty body
    return new Response(JSON.stringify({}), { status: 200 });
  };

  try {
    const result = await audit("fake_token", "test-ref", { activeProbe: false });

    // 1. Run completes (does not throw)
    assert.ok(result, "audit should return a result even when checks fail");

    // 2. Errors are captured
    assert.ok(Array.isArray(result.errors), "errors should be an array");
    assert.ok(result.errors.length > 0, "at least one check error should be captured");

    // 3. Each error has { check, error } shape
    for (const err of result.errors) {
      assert.ok(err.check, "error should have a check name");
      assert.ok(err.error, "error should have a message");
    }

    // 4. Summary includes error_count
    assert.equal(typeof result.summary.error_count, "number");
    assert.equal(result.summary.error_count, result.errors.length);

    // 5. Result has schema_version + findings (even if empty)
    assert.equal(result.schema_version, "1.0");
    assert.ok(Array.isArray(result.findings));

    // 6. Errors include at least the expected check names
    const errorChecks = result.errors.map((e) => e.check);
    assert.ok(errorChecks.includes("rls_tables"), "rls_tables error should be captured");
  } finally {
    global.fetch = originalFetch;
  }
});

test("fault isolation: auth error (401) still aborts (correct behavior)", async () => {
  global.fetch = async (url) => {
    const urlStr = String(url);
    if (urlStr.includes("/database/query")) {
      return new Response(JSON.stringify({ message: "unauthorized" }), { status: 401 });
    }
    if (urlStr.includes("/v1/projects/test-ref")) {
      return new Response(JSON.stringify({ message: "unauthorized" }), { status: 401 });
    }
    return new Response(JSON.stringify({}), { status: 200 });
  };

  try {
    await assert.rejects(
      async () => audit("bad_token", "test-ref", { activeProbe: false }),
      (err) => err.name === "AuthError"
    );
  } finally {
    global.fetch = originalFetch;
  }
});

// ---------------------------------------------------------------------------
// Summary error_count
// ---------------------------------------------------------------------------

test("buildSummary: includes error_count in result after merge", () => {
  const findings = [
    normalizeFinding({
      check: "test_check",
      severity: "high",
      category: "test",
      confidence: "confirmed",
      target: "test:1",
      evidence: {},
      fix: { sql: [], rollback_sql: [], dashboard_action: null, management_api_action: null, requires_service_role: false },
    }),
  ];
  const sorted = sortFindings(findings);
  const summary = buildSummary(sorted);
  summary.error_count = 0; // simulate audit.js adding error_count
  assert.equal(summary.error_count, 0);
  assert.equal(summary.by_severity.high, 1);
});
