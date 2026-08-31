import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { validate } from "../scripts/validate.js";
import {
  findingId,
  SEVERITY_RANK,
  EXIT_CODES,
  normalizeProbe,
  normalizeFinding,
  sortFindings,
  buildSummary,
  scanForSecrets,
  computeExitCode,
  assembleResult,
  classifyError,
} from "../scripts/contract.js";

// Import real check modules to test the full pipeline with real finding shapes
import { classifyTable } from "../scripts/checks/rls.js";
import { probeRpcs, classifyRpc, buildSafePayload, parseArgSignature } from "../scripts/checks/rpc.js";
import { analyzeFunctionBodies } from "../scripts/checks/function-body.js";
import { classifyView } from "../scripts/checks/views.js";

const SCHEMA_PATH = fileURLToPath(new URL("../schema/finding.schema.json", import.meta.url));
const schema = JSON.parse(readFileSync(SCHEMA_PATH, "utf8"));

// ---------------------------------------------------------------------------
// findingId
// ---------------------------------------------------------------------------

test("findingId is deterministic for same check+target", () => {
  const id1 = findingId("rls_disabled", "leaky_table");
  const id2 = findingId("rls_disabled", "leaky_table");
  const id3 = findingId("rls_disabled", "other_table");
  assert.equal(id1, id2, "same inputs must produce same ID");
  assert.notEqual(id1, id3, "different targets must produce different IDs");
  assert.match(id1, /^[0-9a-f]{12}$/);
});

// ---------------------------------------------------------------------------
// normalizeFinding
// ---------------------------------------------------------------------------

test("normalizeFinding adds id + full fix object + references + suppressed", () => {
  const raw = {
    check: "rls_disabled",
    category: "coverage-rls",
    severity: "critical",
    confidence: "confirmed",
    target: "leaky_table",
    evidence: { rls_enabled: false, anon_select: true },
    probe: { status: 200, row_count: 3, bytes: 512 },
    fix: {
      sql: ["ALTER TABLE public.leaky_table ENABLE ROW LEVEL SECURITY;"],
      rollback_sql: [],
      requires_service_role: false,
    },
  };
  const f = normalizeFinding(raw);
  assert.equal(f.id, findingId("rls_disabled", "leaky_table"));
  assert.equal(f.check, "rls_disabled");
  assert.equal(f.severity, "critical");
  assert.equal(f.confidence, "confirmed");
  assert.ok(Array.isArray(f.fix.sql));
  assert.ok(Array.isArray(f.fix.rollback_sql));
  assert.equal(f.fix.sql[0], "ALTER TABLE public.leaky_table ENABLE ROW LEVEL SECURITY;");
  assert.equal(f.fix.requires_service_role, false);
  assert.equal(f.fix.dashboard_action, null);
  assert.equal(f.fix.management_api_action, null);
  assert.deepEqual(f.references, []);
  assert.equal(f.suppressed, false);
  assert.equal(f.suppressed_reason, null);
  assert.ok(f.probe);
  assert.equal(f.probe.status, 200);
  assert.equal(f.probe.bytes, 512);
  assert.equal(f.probe.sample.row_count, 3);
});

test("normalizeFinding normalizes legacy fix_sql string into fix.sql array", () => {
  const raw = {
    check: "storage_bucket_public",
    target: "bucket:media",
    severity: "high",
    confidence: "inferred",
    evidence: {},
    fix_sql: "UPDATE storage.buckets SET public = false;",
  };
  const f = normalizeFinding(raw);
  assert.deepEqual(f.fix.sql, ["UPDATE storage.buckets SET public = false;"]);
  assert.deepEqual(f.fix.rollback_sql, []);
  assert.equal(f.fix_sql, "UPDATE storage.buckets SET public = false;"); // backward-compat
});

test("normalizeFinding with no fix at all gives empty arrays", () => {
  const f = normalizeFinding({ check: "x", target: "y", severity: "low", confidence: "inferred" });
  assert.deepEqual(f.fix.sql, []);
  assert.deepEqual(f.fix.rollback_sql, []);
  assert.equal(f.fix.requires_service_role, false);
});

test("normalizeProbe handles evidence.probe from check modules", () => {
  const raw = {
    evidence: {
      probe: { status: 200, row_count: 5, bytes: 1024 },
    },
  };
  const p = normalizeProbe(raw);
  assert.equal(p.status, 200);
  assert.equal(p.bytes, 1024);
  assert.equal(p.sample.row_count, 5);
  assert.equal(p.sample.columns, null);
});

test("normalizeProbe handles audit.js inline probe shape {confirmed, status, sample}", () => {
  const raw = {
    probe: { confirmed: true, status: 200, sample: { row_count: 2, columns: ["id"], bytes_returned: 50 } },
  };
  const p = normalizeProbe(raw);
  assert.equal(p.status, 200);
  // bytes comes from probe.bytes or sample.bytes_returned
  assert.equal(p.bytes, 50);
  assert.equal(p.sample.row_count, 2);
  assert.deepEqual(p.sample.columns, ["id"]);
});

test("normalizeProbe returns null when no probe data", () => {
  assert.equal(normalizeProbe({ evidence: {} }), null);
  assert.equal(normalizeProbe({}), null);
});

// ---------------------------------------------------------------------------
// sortFindings (deterministic ordering)
// ---------------------------------------------------------------------------

test("sortFindings: severity desc, then check asc, then target asc", () => {
  const findings = [
    { severity: "low", check: "alpha_check", target: "z_table" },
    { severity: "critical", check: "rls_disabled", target: "b_table" },
    { severity: "high", check: "storage_bucket_public", target: "a_bucket" },
    { severity: "critical", check: "rls_disabled", target: "a_table" },
    { severity: "high", check: "rls_permissive_policy", target: "c_table" },
  ];
  const sorted = sortFindings(findings);
  // Critical first, sorted by check then target
  assert.equal(sorted[0].target, "a_table");
  assert.equal(sorted[1].target, "b_table");
  // Then high, sorted by check then target
  assert.equal(sorted[2].check, "rls_permissive_policy");
  assert.equal(sorted[3].check, "storage_bucket_public");
  // Then low
  assert.equal(sorted[4].severity, "low");
});

test("sortFindings does not mutate input array", () => {
  const input = [
    { severity: "low", check: "a", target: "x" },
    { severity: "critical", check: "b", target: "y" },
  ];
  const sorted = sortFindings(input);
  assert.equal(input[0].severity, "low"); // original unchanged
  assert.equal(sorted[0].severity, "critical");
});

// WO-17: sortFindings deduplicates by id (first occurrence wins)
test("sortFindings: deduplicates findings by id (WO-17)", () => {
  const id = "abc123def456";
  const input = [
    { id, severity: "critical", check: "rls_permissive_policy", target: "t1" },
    { id, severity: "high", check: "rls_permissive_policy", target: "t1" }, // duplicate id
    { id: "different", severity: "medium", check: "rls_unindexed_policy_column", target: "t2" },
  ];
  const sorted = sortFindings(input);
  assert.equal(sorted.length, 2, "should drop the duplicate id");
  assert.equal(sorted[0].id, id, "first occurrence wins");
});

// ---------------------------------------------------------------------------
// buildSummary
// ---------------------------------------------------------------------------

test("buildSummary counts by severity + confidence + suppressed", () => {
  const findings = [
    { severity: "critical", confidence: "confirmed", suppressed: false },
    { severity: "high", confidence: "inferred", suppressed: false },
    { severity: "high", confidence: "confirmed", suppressed: true },
    { severity: "medium", confidence: "inferred", suppressed: false },
    { severity: "info", confidence: "inferred", suppressed: false },
  ];
  const s = buildSummary(findings);
  assert.equal(s.by_severity.critical, 1);
  assert.equal(s.by_severity.high, 2);
  assert.equal(s.by_severity.medium, 1);
  assert.equal(s.by_severity.low, 0);
  assert.equal(s.by_severity.info, 1);
  assert.equal(s.confirmed, 2);
  assert.equal(s.inferred, 3);
  assert.equal(s.suppressed, 1);
});

// ---------------------------------------------------------------------------
// scanForSecrets
// ---------------------------------------------------------------------------

test("scanForSecrets detects Pat in JSON string", () => {
  const json = JSON.stringify({ token: "sbp_abc123def456ghi789jkl012mnop" });
  const found = scanForSecrets(json);
  assert.ok(found.some((f) => f.name === "supabase_pat"));
});

test("scanForSecrets detects JWT tokens", () => {
  const json = JSON.stringify({ key: "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dFoiJ8xK7z2q3pP4q0y8z0" });
  const found = scanForSecrets(json);
  assert.ok(found.some((f) => f.name === "jwt_token"));
});

test("scanForSecrets detects DB connection strings", () => {
  const json = JSON.stringify({ url: "postgresql://user:secretpass@db.supabase.co:5432/postgres" });
  const found = scanForSecrets(json);
  assert.ok(found.some((f) => f.name === "db_connstring"));
});

test("scanForSecrets returns empty for clean output", () => {
  const json = JSON.stringify({
    check: "rls_disabled",
    explain: "Without RLS, anon role can read any row.",
    fix_sql: "ALTER TABLE public.my_table ENABLE ROW LEVEL SECURITY;",
    evidence: { rls_enabled: false, anon_select: true },
  });
  assert.equal(scanForSecrets(json).length, 0);
});

test("scanForSecrets does NOT flag 'auth.jwt()' function calls", () => {
  const json = JSON.stringify({ explain: "use auth.jwt() to check the token" });
  assert.equal(scanForSecrets(json).length, 0);
});

// ---------------------------------------------------------------------------
// computeExitCode
// ---------------------------------------------------------------------------

test("exit code 0 when no findings at/above fail-on (default high)", () => {
  const result = { findings: [{ severity: "medium" }, { severity: "low" }] };
  assert.equal(computeExitCode({ errors: {}, result, failOn: "high" }), EXIT_CODES.CLEAN);
});

test("exit code 2 when findings at/above fail-on exist", () => {
  const result = { findings: [{ severity: "high" }, { severity: "low" }] };
  assert.equal(computeExitCode({ errors: {}, result, failOn: "high" }), EXIT_CODES.FINDINGS);
});

test("exit code 2 with critical finding and fail-on=high", () => {
  const result = { findings: [{ severity: "critical" }] };
  assert.equal(computeExitCode({ errors: {}, result, failOn: "high" }), EXIT_CODES.FINDINGS);
});

test("fail-on=critical is stricter than high", () => {
  const result = { findings: [{ severity: "high" }] };
  assert.equal(computeExitCode({ errors: {}, result, failOn: "critical" }), EXIT_CODES.CLEAN);
});

test("exit code 10 on auth error", () => {
  const result = { findings: [] };
  assert.equal(computeExitCode({ errors: { auth_error: true }, result, failOn: "high" }), EXIT_CODES.AUTH_ERROR);
});

test("exit code 11 on network error", () => {
  const result = { findings: [] };
  assert.equal(computeExitCode({ errors: { network_error: true }, result, failOn: "high" }), EXIT_CODES.NETWORK_ERROR);
});

test("exit code 12 on schema violation", () => {
  const result = { findings: [{ severity: "critical" }] };
  assert.equal(computeExitCode({ errors: { schema_violation: true }, result, failOn: "high" }), EXIT_CODES.SCHEMA_VIOLATION);
});

test("fail-on=never always exits 0 even with critical findings", () => {
  const result = { findings: [{ severity: "critical" }] };
  assert.equal(computeExitCode({ errors: {}, result, failOn: "never" }), EXIT_CODES.CLEAN);
});

test("WO-3: incomplete scan (scan_complete=false) exits 2 even with fail-on=never", () => {
  // A tool that fails to enumerate and then looks clean is the worst failure mode.
  const result = { findings: [], scan_complete: false };
  assert.equal(computeExitCode({ errors: {}, result, failOn: "never" }), EXIT_CODES.FINDINGS);
});

test("WO-3: scan_complete undefined (legacy) -> does NOT force failure", () => {
  // Backward compat: snapshots without scan_complete should not be forced to fail.
  const result = { findings: [] };
  assert.equal(computeExitCode({ errors: {}, result, failOn: "high" }), EXIT_CODES.CLEAN);
});

test("suppressed findings are excluded from the fail-gate", () => {
  const result = { findings: [
    { severity: "critical", suppressed: true },
    { severity: "high", suppressed: true },
  ] };
  assert.equal(computeExitCode({ errors: {}, result, failOn: "high" }), EXIT_CODES.CLEAN);
});

test("non-suppressed findings at/above fail-on still trigger exit 2 even when some are suppressed", () => {
  const result = { findings: [
    { severity: "critical", suppressed: true },
    { severity: "high", suppressed: false },
  ] };
  assert.equal(computeExitCode({ errors: {}, result, failOn: "high" }), EXIT_CODES.FINDINGS);
});

test("auth error takes priority over findings", () => {
  const result = { findings: [{ severity: "critical" }] };
  assert.equal(computeExitCode({ errors: { auth_error: true }, result, failOn: "high" }), EXIT_CODES.AUTH_ERROR);
});

// ---------------------------------------------------------------------------
// Entry 35: confidence-calibrated severity
// ---------------------------------------------------------------------------

test("buildSummary includes confirmed_by_severity and inferred_by_severity", () => {
  const findings = [
    { severity: "critical", confidence: "confirmed", suppressed: false },
    { severity: "critical", confidence: "inferred", suppressed: false },
    { severity: "high", confidence: "confirmed", suppressed: false },
    { severity: "high", confidence: "inferred", suppressed: false },
    { severity: "medium", confidence: "confirmed", suppressed: false },
    { severity: "low", confidence: "inferred", suppressed: false },
  ];
  const s = buildSummary(findings);
  assert.equal(s.confirmed_by_severity.critical, 1);
  assert.equal(s.inferred_by_severity.critical, 1);
  assert.equal(s.confirmed_by_severity.high, 1);
  assert.equal(s.inferred_by_severity.high, 1);
  assert.equal(s.confirmed_by_severity.medium, 1);
  assert.equal(s.inferred_by_severity.low, 1);
  assert.equal(s.confirmed_by_severity.low, 0);
  assert.equal(s.inferred_by_severity.medium, 0);
});

test("computeExitCode with confirmedOnly: true ignores inferred findings", () => {
  // Large-inferred-surface case: 96 inferred RPC grants (gated, not exploitable) + 0 confirmed
  const result = {
    findings: Array.from({ length: 96 }, () => ({
      severity: "critical", confidence: "inferred", suppressed: false,
    })),
  };
  const code = computeExitCode({ errors: {}, result, failOn: "critical", confirmedOnly: true });
  assert.equal(code, EXIT_CODES.CLEAN, "inferred-only findings should NOT trigger exit 2 with confirmedOnly");
});

test("computeExitCode with confirmedOnly: true still fails on confirmed findings", () => {
  const result = {
    findings: [
      { severity: "high", confidence: "inferred", suppressed: false },
      { severity: "critical", confidence: "confirmed", suppressed: false },
    ],
  };
  const code = computeExitCode({ errors: {}, result, failOn: "high", confirmedOnly: true });
  assert.equal(code, EXIT_CODES.FINDINGS, "confirmed high finding should trigger exit 2");
});

test("computeExitCode with confirmedOnly: true still excludes suppressed confirmed", () => {
  const result = {
    findings: [
      { severity: "critical", confidence: "confirmed", suppressed: true },
    ],
  };
  const code = computeExitCode({ errors: {}, result, failOn: "critical", confirmedOnly: true });
  assert.equal(code, EXIT_CODES.CLEAN, "suppressed confirmed findings are excluded");
});

test("computeExitCode without confirmedOnly (default) fails on inferred findings at/above fail-on", () => {
  // Default behavior: both confirmed AND inferred count toward fail-on
  const result = {
    findings: [
      { severity: "high", confidence: "inferred", suppressed: false },
    ],
  };
  const code = computeExitCode({ errors: {}, result, failOn: "high" });
  assert.equal(code, EXIT_CODES.FINDINGS, "default mode counts inferred findings");
});

test("divergent-grantee case: large inferred, small/zero confirmed reported distinctly", () => {
  const findings = [
    // 96 inferred RPC grants (gated by internal auth checks, not exploitable)
    ...Array.from({ length: 96 }, () => ({
      severity: "high", confidence: "inferred", suppressed: false,
    })),
    // 0 confirmed — all gated, none proven exploitable
  ];
  const s = buildSummary(findings);
  assert.equal(s.confirmed, 0, "zero confirmed leaks");
  assert.equal(s.inferred, 96, "96 inferred grants");
  assert.equal(s.inferred_by_severity.high, 96);
  assert.equal(s.confirmed_by_severity.high, 0);
  // With confirmedOnly, the large inferred count does NOT fail the gate
  assert.equal(
    computeExitCode({ errors: {}, result: { findings }, failOn: "high", confirmedOnly: true }),
    EXIT_CODES.CLEAN
  );
  // Without confirmedOnly, the inferred count DOES fail the gate
  assert.equal(
    computeExitCode({ errors: {}, result: { findings }, failOn: "high" }),
    EXIT_CODES.FINDINGS
  );
});

// ---------------------------------------------------------------------------
// classifyError
// ---------------------------------------------------------------------------

test("classifyError: 401 -> auth_error", () => {
  assert.equal(classifyError(new Error("SQL 401: Unauthorized")), "auth_error");
});

test("classifyError: 403 -> auth_error", () => {
  assert.equal(classifyError(new Error("SQL 403: Forbidden")), "auth_error");
});

test("classifyError: ENOTFOUND -> network_error", () => {
  assert.equal(classifyError(new Error("fetch ENOTFOUND api.supabase.com")), "network_error");
});

test("classifyError: ECONNREFUSED -> network_error", () => {
  assert.equal(classifyError(new Error("fetch ECONNREFUSED 127.0.0.1:443")), "network_error");
});

// ---------------------------------------------------------------------------
// Full schema validation: real check-module findings through the contract
// ---------------------------------------------------------------------------

test("rls_permissive_policy finding passes schema after normalization", () => {
  const table = {
    table_name: "sensitive_photos",
    rls_enabled: true,
    policies: [
      { policyname: "Allow public access", cmd: "ALL", roles: "{public}", qual: "true", with_check: null },
    ],
    anon_select: true,
    anon_insert: false,
    anon_delete: false,
    auth_select: false,
    sensitive_columns: ["patient_cpf"],
  };
  const raw = classifyTable(table, { status: 200, rowCount: 1, bytes: 256 });
  assert.ok(raw, "classifyTable should return a finding");
  const f = normalizeFinding(raw);
  const result = assembleResult({
    project_ref: "testref01",
    mode: "audit-passive",
    rawFindings: [f],
  });
  const { valid, errors } = validate(result, schema);
  assert.equal(valid, true, `schema violations: ${JSON.stringify(errors)}`);
});

test("rpc finding passes schema after normalization", async () => {
  const fn = {
    function_name: "get_data",
    prosecdef: true,
    provolatile: "s",
    return_type: "TABLE",
    anon_execute: true,
    auth_execute: false,
    config: [],
    args: parseArgSignature("user_id uuid, limit integer"),
  };
  const { findings } = await probeRpcs([fn], async () => ({
    status: 200,
    body: JSON.stringify([{ id: 1, name: "test" }]),
  }));
  const f = normalizeFinding(findings[0]);
  const result = assembleResult({
    project_ref: "testref01",
    mode: "audit-active",
    rawFindings: [f],
  });
  const { valid, errors } = validate(result, schema);
  assert.equal(valid, true, `schema violations: ${JSON.stringify(errors)}`);
});

test("function-body finding passes schema after normalization", () => {
  const fn = {
    function_name: "secrecy_filter",
    prosecdef: true,
    body: "BEGIN RETURN query$SELECT * FROM accounts WHERE id = $1; END;",
    config: [],
    anon_execute: true,
    auth_execute: false,
  };
  const findings = analyzeFunctionBodies([fn]);
  assert.ok(findings.length > 0);
  const normalized = findings.map(normalizeFinding);
  const result = assembleResult({
    project_ref: "testref01",
    mode: "audit-passive",
    rawFindings: normalized,
  });
  const { valid, errors } = validate(result, schema);
  assert.equal(valid, true, `schema violations: ${JSON.stringify(errors)}`);
});

test("view finding passes schema after normalization", () => {
  const view = {
    view_name: "v_leaky",
    matview: false,
    security_invoker: false,
    anon_select: true,
    auth_select: false,
    columns: ["id", "email", "cpf"],
  };
  const findings = classifyView(view, { status: 200, rowCount: 1, bytes: 100 });
  const normalized = findings.map(normalizeFinding);
  const result = assembleResult({
    project_ref: "testref01",
    mode: "audit-active",
    rawFindings: normalized,
  });
  const { valid, errors } = validate(result, schema);
  assert.equal(valid, true, `schema violations: ${JSON.stringify(errors)}`);
});

test("full result from mixed check modules passes schema + contains no secrets", () => {
  // Build a realistic result from all check module types
  const table = {
    table_name: "sensitive_photos",
    rls_enabled: true,
    policies: [
      { policyname: "p", cmd: "ALL", roles: "{public}", qual: "true", with_check: null },
    ],
    anon_select: true,
    anon_insert: false,
    anon_delete: false,
    auth_select: false,
    sensitive_columns: ["cpf"],
  };
  const view = {
    view_name: "v_pii",
    matview: false,
    security_invoker: false,
    anon_select: true,
    auth_select: false,
    columns: ["email"],
  };
  const secdefFn = {
    function_name: "do_admin_thing",
    prosecdef: true,
    body: "BEGIN RETURN; END;",
    config: [],
    anon_execute: true,
    auth_execute: false,
  };

  const tableFinding = classifyTable(table, { status: 200, rowCount: 1, bytes: 128 });
  const viewFindings = classifyView(view, null);
  const fnFindings = analyzeFunctionBodies([secdefFn]);

  const rawFindings = [
    normalizeFinding(tableFinding),
    ...viewFindings.map(normalizeFinding),
    ...fnFindings.map(normalizeFinding),
  ];

  const result = assembleResult({
    project_ref: "xyz789",
    mode: "audit-active",
    rawFindings,
  });

  // 1. Schema validation
  const { valid, errors } = validate(result, schema);
  assert.equal(valid, true, `schema violations: ${JSON.stringify(errors)}`);

  // 2. No secrets in output
  const jsonStr = JSON.stringify(result);
  const secrets = scanForSecrets(jsonStr);
  assert.equal(secrets.length, 0, `secrets found in output: ${JSON.stringify(secrets)}`);

  // 3. Deterministic ordering — run twice, assert identical (fixed timestamp)
  const fixedAt = "2026-01-01T00:00:00.000Z";
  const opts = { project_ref: "xyz789", mode: "audit-active", rawFindings, generated_at: fixedAt };
  const json1 = JSON.stringify(assembleResult(opts), null, 2);
  const json2 = JSON.stringify(assembleResult(opts), null, 2);
  assert.equal(json1, json2, "output must be deterministic");
});

test("errors array is accepted in schema (fault isolation)", () => {
  const result = {
    ...assembleResult({ project_ref: "abc", mode: "audit-passive", rawFindings: [] }),
    errors: [{ check: "storage_bucket_public", error: "SQL 500: internal error" }],
  };
  const { valid, errors: violations } = validate(result, schema);
  assert.equal(valid, true, `schema violations: ${JSON.stringify(violations)}`);
});

// === details -> evidence (2026-08-31) ===
// Check modules are inconsistent about the key they build. Reading only `evidence`
// dropped `details` on the floor: function_secdef_missing_auth_check shipped
// `evidence: {}`, so its auth_check grade never reached any consumer.

test("normalizeFinding: falls back to raw.details when a check builds details", () => {
  const f = normalizeFinding({
    check: "function_secdef_missing_auth_check",
    target: "promote_to_admin",
    severity: "high",
    details: { auth_check: "weak", reason: "only a bare user_id mention" },
  });
  assert.equal(f.evidence.auth_check, "weak");
  assert.equal(f.evidence.reason, "only a bare user_id mention");
});

test("normalizeFinding: explicit evidence still wins over details", () => {
  const f = normalizeFinding({
    check: "x", target: "t",
    evidence: { a: 1 },
    details: { b: 2 },
  });
  assert.deepEqual(f.evidence, { a: 1 });
});

test("normalizeFinding: neither present -> empty object, not undefined", () => {
  const f = normalizeFinding({ check: "x", target: "t" });
  assert.deepEqual(f.evidence, {});
});
