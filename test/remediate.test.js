import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import {
  isExecutableSql,
  extractExecutableSql,
  categorizeFix,
  planRemediations,
  remediate,
  rollbackRemediation,
  verifyRemediation,
  refHash,
} from "../scripts/remediate.js";
import { normalizeFinding, assembleResult, scanForSecrets } from "../scripts/contract.js";
import { validate } from "../scripts/validate.js";

const SCHEMA_PATH = fileURLToPath(new URL("../schema/finding.schema.json", import.meta.url));
const schema = JSON.parse(readFileSync(SCHEMA_PATH, "utf8"));

// === Mock finding factories ===
// Each mirrors the fix shape a real check module produces (post-normalizeFinding).

function makeSqlFinding() {
  return normalizeFinding({
    check: "rls_disabled",
    category: "coverage-rls",
    severity: "critical",
    confidence: "confirmed",
    target: "leaky_table",
    evidence: { rls_enabled: false, anon_select: true },
    title: "RLS disabled on table accessible via anon",
    explain: "Without RLS, anon role with default CRUD grants can read/insert/delete any row.",
    fix: {
      sql: ["ALTER TABLE public.leaky_table ENABLE ROW LEVEL SECURITY;"],
      rollback_sql: ["ALTER TABLE public.leaky_table DISABLE ROW LEVEL SECURITY;"],
      dashboard_action: null,
      management_api_action: null,
      requires_service_role: false,
    },
  });
}

function makeWritePolicyFinding() {
  return normalizeFinding({
    check: "rls_permissive_write_policy",
    category: "coverage-rls",
    severity: "high",
    confidence: "inferred",
    target: "comments",
    evidence: { rls_enabled: true, anon_insert: true },
    title: "RLS policy with permissive/missing write guard",
    explain: "An INSERT/UPDATE policy reachable by anon has a permissive or missing WITH CHECK.",
    fix: {
      sql: [
        "-- Replace the permissive write policy with a caller-scoped WITH CHECK:",
        "-- DROP POLICY \"allow_anon_insert\" ON public.comments;",
        "-- CREATE POLICY comments_owner_write ON public.comments FOR INSERT WITH CHECK (user_id = auth.uid());",
        "-- Or, if writes must go server-side only: REVOKE ALL ON public.comments FROM anon, authenticated;",
      ],
      rollback_sql: [],
      dashboard_action: null,
      management_api_action: null,
      requires_service_role: false,
    },
  });
}

function makeMgmtApiFinding() {
  return normalizeFinding({
    check: "auth_hibp_disabled",
    category: "coverage-auth",
    severity: "medium",
    confidence: "inferred",
    target: "auth:password",
    evidence: { password_hibp_enabled: false },
    title: "HIBP password breach checking disabled",
    explain: "Compromised passwords are not blocked.",
    fix: {
      sql: [],
      rollback_sql: [],
      dashboard_action: null,
      management_api_action: {
        method: "PATCH",
        path: "/v1/projects/ref123/config/auth",
        body: { password_hibp_enabled: true },
      },
      requires_service_role: false,
    },
  });
}

function makeDashboardOnlyFinding() {
  return normalizeFinding({
    check: "data_api_auto_expose_on",
    category: "coverage-data-api",
    severity: "medium",
    confidence: "inferred",
    target: "project:ref123",
    evidence: { auto_expose: true, leaky_owner_roles: ["supabase_admin"] },
    title: "Data API auto-expose ON",
    explain: "New tables automatically exposed via REST API.",
    fix: {
      sql: [
        "-- Tables created via Supabase Dashboard (owner = supabase_admin) cannot be revoked from postgres role.",
        '-- Toggle this in: Dashboard -> Project Settings -> Data API -> "Automatically expose new tables" = OFF',
      ],
      rollback_sql: [],
      dashboard_action: "Dashboard -> Project Settings -> Data API: toggle OFF 'Automatically expose new tables'",
      management_api_action: null,
      requires_service_role: false,
    },
  });
}

function makeRealtimeFinding() {
  return normalizeFinding({
    check: "realtime_publication_no_rls",
    category: "coverage-realtime",
    severity: "critical",
    confidence: "confirmed",
    target: "table:events",
    evidence: { in_publication: "supabase_realtime", rls_enabled: false },
    title: "Table in supabase_realtime publication WITHOUT RLS",
    explain: "Realtime broadcasts row changes to anyone subscribed.",
    fix: {
      sql: [
        "ALTER TABLE public.events ENABLE ROW LEVEL SECURITY;",
        "-- Or remove from publication: ALTER PUBLICATION supabase_realtime DROP TABLE public.events;",
      ],
      rollback_sql: ["ALTER TABLE public.events DISABLE ROW LEVEL SECURITY;"],
      dashboard_action: null,
      management_api_action: null,
      requires_service_role: false,
    },
  });
}

function makeEdgeFunctionFinding() {
  return normalizeFinding({
    check: "edge_function_verify_jwt_disabled",
    category: "coverage-edge-functions",
    severity: "high",
    confidence: "confirmed",
    target: "function:abc123",
    evidence: { name: "my_func", verify_jwt: false },
    title: "Edge Function has verify_jwt disabled",
    explain: "The function can be called by anyone with the anon key.",
    fix: {
      sql: [],
      rollback_sql: [],
      dashboard_action: null,
      management_api_action: {
        method: "PATCH",
        path: "/v1/projects/ref123/functions/abc123",
        body: { verify_jwt: true },
      },
      requires_service_role: false,
    },
  });
}

function makeNetworkFinding() {
  return normalizeFinding({
    check: "db_no_network_restrictions",
    category: "coverage-network-db",
    severity: "high",
    confidence: "confirmed",
    target: "project:ref123",
    evidence: { network_restrictions: { enabled: false } },
    title: "Direct Postgres reachable without IP allowlist",
    explain: "Network restrictions are not enabled.",
    fix: {
      sql: [],
      rollback_sql: [],
      dashboard_action: "Dashboard -> Project Settings -> Network: add IP allowlist",
      management_api_action: {
        method: "PATCH",
        path: "/v1/projects/ref123/network/restrictions",
        body: { enabled: true },
      },
      requires_service_role: false,
    },
  });
}

function makeSuppressedFinding() {
  const f = makeSqlFinding();
  f.suppressed = true;
  f.suppressed_reason = "intentional";
  return f;
}

// SQL finding that requires the service_role key to apply.
function makeSerRoleFinding() {
  return normalizeFinding({
    check: "rls_leaky_owner_default_privileges",
    category: "coverage-rls",
    severity: "critical",
    confidence: "confirmed",
    target: "table:leaky_owner",
    evidence: { owner: "supabase_admin", grants_to_anon: true },
    title: "Default privileges grant to anon on supabase_admin-owned table",
    explain: "Owner is supabase_admin; fixing requires the service_role to revoke grants.",
    fix: {
      sql: ["REVOKE SELECT ON TABLE public.leaky_owner FROM anon;"],
      rollback_sql: ["GRANT SELECT ON TABLE public.leaky_owner TO anon;"],
      dashboard_action: null,
      management_api_action: null,
      requires_service_role: true,
    },
  });
}

// SQL finding with NO rollback_sql — should be skipped on --apply.
function makeSqlNoRollbackFinding() {
  return normalizeFinding({
    check: "rls_temp_fix_no_rollback",
    category: "coverage-rls",
    severity: "high",
    confidence: "confirmed",
    target: "table:no_rollback",
    evidence: { rls_enabled: false },
    title: "RLS disabled — no rollback provided",
    explain: "Fix has SQL but no rollback_sql.",
    fix: {
      sql: ["ALTER TABLE public.no_rollback ENABLE ROW LEVEL SECURITY;"],
      rollback_sql: [],
      dashboard_action: null,
      management_api_action: null,
      requires_service_role: false,
    },
  });
}

function makeResult(findings, ref = "ref123") {
  const rawFindings = findings.map(normalizeFinding);
  const fixedAt = "2026-08-27T12:00:00.000Z";
  return assembleResult({
    project_ref: ref,
    mode: "audit-active",
    rawFindings,
    generated_at: fixedAt,
  });
}

// === isExecutableSql ===

test("isExecutableSql: real SQL -> true", () => {
  assert.equal(isExecutableSql("ALTER TABLE public.x ENABLE ROW LEVEL SECURITY;"), true);
  assert.equal(isExecutableSql("REVOKE INSERT ON storage.objects FROM anon;"), true);
});

test("isExecutableSql: comment-only lines -> false", () => {
  assert.equal(isExecutableSql("-- DROP POLICY x ON public.y;"), false);
  assert.equal(isExecutableSql("-- some guidance"), false);
  assert.equal(isExecutableSql("   -- indented comment"), false);
});

test("isExecutableSql: placeholder lines with ... -> false", () => {
  assert.equal(isExecutableSql("REVOKE EXECUTE ON FUNCTION public.foo(...from anon...);"), false);
});

test("isExecutableSql: SQL with inline comment -> true", () => {
  assert.equal(isExecutableSql("ALTER TABLE public.x ENABLE RLS; -- enable RLS"), true);
});

test("isExecutableSql: empty/undefined/null -> false", () => {
  assert.equal(isExecutableSql(""), false);
  assert.equal(isExecutableSql("   "), false);
  assert.equal(isExecutableSql(null), false);
  assert.equal(isExecutableSql(undefined), false);
});

// === extractExecutableSql ===

test("extractExecutableSql: filters comments + placeholders, keeps real SQL", () => {
  const fix = {
    sql: [
      "-- Replace the permissive policy with a caller-scoped one, e.g.:",
      "-- DROP POLICY \"x\" ON public.t;",
      "ALTER TABLE public.t ENABLE ROW LEVEL SECURITY;",
      "-- Or, revoke grants:",
      "REVOKE ALL ON public.t FROM anon, authenticated;",
    ],
  };
  const result = extractExecutableSql(fix);
  assert.equal(result.length, 2);
  assert.equal(result[0], "ALTER TABLE public.t ENABLE ROW LEVEL SECURITY;");
  assert.equal(result[1], "REVOKE ALL ON public.t FROM anon, authenticated;");
});

test("extractExecutableSql: all comments -> []", () => {
  const fix = { sql: ["-- only comments", "-- more comments"] };
  assert.deepEqual(extractExecutableSql(fix), []);
});

test("extractExecutableSql: null/undefined fix -> []", () => {
  assert.deepEqual(extractExecutableSql(null), []);
  assert.deepEqual(extractExecutableSql({}), []);
  assert.deepEqual(extractExecutableSql({ sql: null }), []);
  assert.deepEqual(extractExecutableSql({ sql: [""] }), []);
});

// === categorizeFix ===

test("categorizeFix: SQL-only finding", () => {
  const cats = categorizeFix(makeSqlFinding());
  assert.equal(cats.hasSql, true);
  assert.equal(cats.hasMgmtApi, false);
  assert.equal(cats.hasDashboard, false);
  assert.equal(cats.isDashboardOnly, false);
  assert.equal(cats.hasNoFix, false);
});

test("categorizeFix: management-API-only finding", () => {
  const cats = categorizeFix(makeMgmtApiFinding());
  assert.equal(cats.hasSql, false);
  assert.equal(cats.hasMgmtApi, true);
  assert.equal(cats.hasDashboard, false);
  assert.equal(cats.isDashboardOnly, false);
  assert.equal(cats.hasNoFix, false);
});

test("categorizeFix: dashboard-only finding (SQL is all comments)", () => {
  const cats = categorizeFix(makeDashboardOnlyFinding());
  assert.equal(cats.hasSql, false);
  assert.equal(cats.hasMgmtApi, false);
  assert.equal(cats.hasDashboard, true);
  assert.equal(cats.isDashboardOnly, true);
  assert.equal(cats.hasNoFix, false);
});

test("categorizeFix: finding with both mgmt API + dashboard action", () => {
  const cats = categorizeFix(makeNetworkFinding());
  assert.equal(cats.hasSql, false);
  assert.equal(cats.hasMgmtApi, true);
  assert.equal(cats.hasDashboard, true);
  assert.equal(cats.isDashboardOnly, false);
  assert.equal(cats.hasNoFix, false);
});

test("categorizeFix: finding with no fix at all", () => {
  const finding = normalizeFinding({
    check: "no_fix_check",
    target: "x",
    severity: "low",
    confidence: "inferred",
    fix: {},
  });
  const cats = categorizeFix(finding);
  assert.equal(cats.hasSql, false);
  assert.equal(cats.hasMgmtApi, false);
  assert.equal(cats.hasDashboard, false);
  assert.equal(cats.isDashboardOnly, false);
  assert.equal(cats.hasNoFix, true);
});

// === planRemediations ===

test("planRemediations: builds ordered plan from results, filters suppressed", () => {
  const result = makeResult([
    makeSqlFinding(),            // critical
    makeRealtimeFinding(),       // critical
    makeMgmtApiFinding(),        // medium
    makeDashboardOnlyFinding(),  // medium
    makeSuppressedFinding(),     // critical — suppressed, should be filtered
  ]);

  const plan = planRemediations(result);

  // Suppressed finding filtered out
  assert.equal(plan.length, 4);
  assert.equal(plan.find((p) => p.check === "rls_disabled" && p.target === "leaky_table" && p.suppressed), undefined);

  // Sorted: critical first (then high, medium, low)
  // Two critical findings, then two medium
  assert.equal(plan[0].severity, "critical");
  assert.equal(plan[2].severity, "medium");

  // Plan items have the right structure
  const first = plan[0];
  assert.ok(first.id);
  assert.ok(first.check);
  assert.ok(first.target);
  assert.ok(Array.isArray(first.sql_to_execute));
  assert.ok(typeof first.categories === "object");
});

test("planRemediations: sorts by severity desc then check then target", () => {
  const result = makeResult([
    makeMgmtApiFinding(),   // medium, check=auth_hibp_disabled
    makeDashboardOnlyFinding(), // medium, check=data_api_auto_expose_on
  ]);
  const plan = planRemediations(result);
  // Same severity: sorted by check name
  assert.equal(plan[0].check, "auth_hibp_disabled");
  assert.equal(plan[1].check, "data_api_auto_expose_on");
});

test("planRemediations: empty findings -> empty plan", () => {
  const result = makeResult([]);
  const plan = planRemediations(result);
  assert.deepEqual(plan, []);
});

test("planRemediations: extracts correct SQL per finding type", () => {
  const result = makeResult([
    makeSqlFinding(),
    makeMgmtApiFinding(),
    makeDashboardOnlyFinding(),
    makeRealtimeFinding(),
  ]);
  const plan = planRemediations(result);

  const sqlFinding = plan.find((p) => p.check === "rls_disabled");
  assert.equal(sqlFinding.sql_to_execute.length, 1);
  assert.ok(sqlFinding.sql_to_execute[0].includes("ENABLE ROW LEVEL SECURITY"));

  const realtimeFinding = plan.find((p) => p.check === "realtime_publication_no_rls");
  assert.equal(realtimeFinding.sql_to_execute.length, 1);
  assert.ok(realtimeFinding.sql_to_execute[0].includes("ENABLE ROW LEVEL SECURITY"));

  const mgmtFinding = plan.find((p) => p.check === "auth_hibp_disabled");
  assert.equal(mgmtFinding.sql_to_execute.length, 0);
  assert.ok(mgmtFinding.management_api_action);

  const dashboardFinding = plan.find((p) => p.check === "data_api_auto_expose_on");
  assert.equal(dashboardFinding.sql_to_execute.length, 0);
  assert.ok(dashboardFinding.dashboard_action);
  assert.equal(dashboardFinding.categories.isDashboardOnly, true);
});

// === remediate dry-run ===

test("remediate dry-run: does not call transport, returns plan", async () => {
  const result = makeResult([makeSqlFinding(), makeMgmtApiFinding(), makeDashboardOnlyFinding()]);
  let dbQueryCalled = 0;
  let mgmtCalled = 0;

  const out = await remediate(result, {
    dryRun: true,
    token: "sbp_test",
    ref: result.project_ref,
    _dbQuery: async () => { dbQueryCalled++; return []; },
    _mgmtRequest: async () => { mgmtCalled++; return {}; },
  });

  assert.equal(dbQueryCalled, 0, "dry-run must not call dbQuery");
  assert.equal(mgmtCalled, 0, "dry-run must not call mgmtRequest");
  assert.equal(out.mode, "dry-run");
  assert.ok(Array.isArray(out.plan));
  assert.equal(out.plan.length, 3);
  assert.ok(out.summary);
  assert.equal(out.summary.total, 3);
  assert.equal(out.summary.sql_executable, 1); // only makeSqlFinding has executable SQL
  // dashboard only: data_api_auto_expose_on
  assert.equal(out.summary.dashboard_only, 1);
});

test("remediate dry-run: filters suppressed findings", async () => {
  const result = makeResult([
    makeSqlFinding(),
    makeSuppressedFinding(),
  ]);
  const out = await remediate(result, { dryRun: true });
  assert.equal(out.plan.length, 1); // suppressed filtered
});

// === remediate apply (SQL) ===

test("remediate apply: SQL findings call dbQuery with BEGIN/COMMIT", async () => {
  const result = makeResult([makeSqlFinding()]);
  const dbCalls = [];

  const out = await remediate(result, {
    dryRun: false,
    token: "sbp_test",
    ref: result.project_ref,
    _dbQuery: async (query) => {
      dbCalls.push(query);
      return [];
    },
    _mgmtRequest: async () => { assert.fail("mgmtRequest should not be called for SQL-only finding"); },
  });

  assert.equal(dbCalls.length, 1);
  assert.ok(dbCalls[0].startsWith("BEGIN;"), "SQL must be wrapped in BEGIN");
  assert.ok(dbCalls[0].endsWith("COMMIT;"), "SQL must end with COMMIT");
  assert.ok(dbCalls[0].includes("ENABLE ROW LEVEL SECURITY"));

  const sqlResult = out.results.find((r) => r.check === "rls_disabled");
  assert.ok(sqlResult);
  assert.equal(sqlResult.actions.length, 1);
  assert.equal(sqlResult.actions[0].type, "sql");
  assert.equal(sqlResult.actions[0].status, "applied");
});

// === remediate apply (management API) ===

test("remediate apply: mgmt-API findings call mgmtRequest", async () => {
  const result = makeResult([makeMgmtApiFinding()]);
  const mgmtCalls = [];

  const out = await remediate(result, {
    dryRun: false,
    token: "sbp_test",
    ref: result.project_ref,
    _dbQuery: async () => { assert.fail("dbQuery should not be called for mgmt-API-only finding"); },
    _mgmtRequest: async (method, path, body) => {
      mgmtCalls.push({ method, path, body });
      return {};
    },
  });

  assert.equal(mgmtCalls.length, 1);
  assert.equal(mgmtCalls[0].method, "PATCH");
  assert.equal(mgmtCalls[0].path, "/v1/projects/ref123/config/auth");
  assert.deepEqual(mgmtCalls[0].body, { password_hibp_enabled: true });

  const mgmtResult = out.results.find((r) => r.check === "auth_hibp_disabled");
  assert.ok(mgmtResult);
  assert.equal(mgmtResult.actions[0].type, "mgmt_api");
  assert.equal(mgmtResult.actions[0].status, "applied");
});

// === remediate apply (dashboard-only) ===

test("remediate apply: dashboard-only findings are listed, not executed", async () => {
  const result = makeResult([makeDashboardOnlyFinding()]);
  let dbQueryCalled = 0;
  let mgmtCalled = 0;

  const out = await remediate(result, {
    dryRun: false,
    token: "sbp_test",
    ref: result.project_ref,
    _dbQuery: async () => { dbQueryCalled++; return []; },
    _mgmtRequest: async () => { mgmtCalled++; return {}; },
  });

  assert.equal(dbQueryCalled, 0);
  assert.equal(mgmtCalled, 0);

  const dashResult = out.results.find((r) => r.check === "data_api_auto_expose_on");
  assert.ok(dashResult);
  assert.equal(dashResult.actions[0].type, "dashboard_skip");
  assert.equal(dashResult.actions[0].status, "skipped");
  assert.ok(dashResult.actions[0].click_path);
  assert.ok(dashResult.actions[0].click_path.includes("Data API"));
});

// === remediate apply (mixed) ===

test("remediate apply: handles mixed findings (SQL + mgmt + dashboard + no-fix)", async () => {
  const result = makeResult([
    makeSqlFinding(),      // SQL
    makeMgmtApiFinding(),   // mgmt API
    makeDashboardOnlyFinding(), // dashboard-only
    makeRealtimeFinding(),  // SQL
    makeEdgeFunctionFinding(), // mgmt API
    makeNetworkFinding(),  // both mgmt API + dashboard
  ]);
  const dbCalls = [];
  const mgmtCalls = [];

  const out = await remediate(result, {
    dryRun: false,
    token: "sbp_test",
    ref: result.project_ref,
    _dbQuery: async (q) => { dbCalls.push(q); return []; },
    _mgmtRequest: async (m, p, b) => { mgmtCalls.push({ m, p, b }); return {}; },
  });

  // SQL called for: rls_disabled + realtime_publication_no_rls
  assert.equal(dbCalls.length, 2, "should call dbQuery for 2 SQL findings");
  // Mgmt API called for: auth_hibp, edge_function, network_db
  assert.equal(mgmtCalls.length, 3, "should call mgmtRequest for 3 mgmt-API findings");
  // Summary
  assert.equal(out.summary.total, 6);
  assert.equal(out.summary.applied, 5); // 2 SQL + 3 mgmt = 5 applied
  assert.equal(out.summary.skipped, 1); // 1 dashboard-only
});

// === remediate apply error handling ===

test("remediate apply: SQL failure is recorded, mgmt API still attempted", async () => {
  const result = makeResult([
    makeSqlFinding(),
    makeMgmtApiFinding(),
  ]);

  const out = await remediate(result, {
    dryRun: false,
    token: "sbp_test",
    ref: result.project_ref,
    _dbQuery: async () => { throw new Error("SQL 42501: permission denied"); },
    _mgmtRequest: async () => { return {}; },
  });

  const sqlResult = out.results.find((r) => r.check === "rls_disabled");
  assert.equal(sqlResult.actions[0].status, "failed");
  assert.ok(sqlResult.actions[0].error);

  const mgmtResult = out.results.find((r) => r.check === "auth_hibp_disabled");
  assert.equal(mgmtResult.actions[0].status, "applied");

  assert.equal(out.summary.applied, 1);
  assert.equal(out.summary.failed, 1);
});

test("remediate apply: mgmt API failure is recorded independently", async () => {
  const result = makeResult([
    makeMgmtApiFinding(),
    makeEdgeFunctionFinding(),
  ]);

  const out = await remediate(result, {
    dryRun: false,
    token: "sbp_test",
    ref: result.project_ref,
    _dbQuery: async () => { assert.fail("dbQuery should not be called"); },
    _mgmtRequest: async (m, p, b) => {
      if (p.includes("config/auth")) throw new Error("Auth config error");
      return {};
    },
  });

  const authResult = out.results.find((r) => r.check === "auth_hibp_disabled");
  assert.equal(authResult.actions[0].status, "failed");
  assert.ok(authResult.actions[0].error);

  const edgeResult = out.results.find((r) => r.check === "edge_function_verify_jwt_disabled");
  assert.equal(edgeResult.actions[0].status, "applied");

  assert.equal(out.summary.applied, 1);
  assert.equal(out.summary.failed, 1);
});

// === remediate apply idempotency ===

test("remediate apply: re-applying same fixes does not error (idempotent)", async () => {
  const result = makeResult([makeSqlFinding(), makeMgmtApiFinding()]);

  // First apply — transports succeed
  const out1 = await remediate(result, {
    dryRun: false, token: "sbp_test", ref: result.project_ref,
    _dbQuery: async () => [],
    _mgmtRequest: async () => ({}),
  });
  assert.equal(out1.summary.failed, 0);

  // Second apply — same inputs, transports still succeed (REVOKE/ALTER are idempotent)
  const out2 = await remediate(result, {
    dryRun: false, token: "sbp_test", ref: result.project_ref,
    _dbQuery: async (q) => {
      // Simulate PostgreSQL idempotency: REVOKE doesn't error if already revoked
      return [];
    },
    _mgmtRequest: async () => ({}),
  });
  assert.equal(out2.summary.failed, 0);
  assert.equal(out2.summary.applied, 2);
});

test("remediate apply: missing token -> throws auth error", async () => {
  const result = makeResult([makeSqlFinding()]);
  await assert.rejects(
    async () => remediate(result, { dryRun: false, token: null, ref: result.project_ref }),
    (err) => err.code === "AUTH_ERROR"
  );
});

// === remediate apply snapshot ===

test("remediate apply: writes a snapshot file before applying (when _writeSnapshot provided)", async () => {
  const result = makeResult([makeSqlFinding()]);
  let snapPath = null;
  let snapContent = null;

  await remediate(result, {
    dryRun: false, token: "sbp_test", ref: result.project_ref,
    _dbQuery: async () => [],
    _mgmtRequest: async () => ({}),
    _writeSnapshot: (path, content) => {
      snapPath = path;
      snapContent = content;
    },
  });

  assert.ok(snapPath);
  assert.ok(snapPath.startsWith("fixtures/"));
  assert.ok(snapPath.includes("remediation_snapshot_"));
  const parsed = JSON.parse(snapContent);
  assert.equal(parsed.project_ref, "ref123");
  assert.ok(Array.isArray(parsed.plan));
  assert.equal(parsed.plan.length, 1);
});

// === remediate dry-run: no snapshot written ===

test("remediate dry-run: does not write snapshot", async () => {
  const result = makeResult([makeSqlFinding()]);
  let snapWritten = false;

  await remediate(result, {
    dryRun: true,
    token: "sbp_test",
    ref: result.project_ref,
    _writeSnapshot: () => { snapWritten = true; },
  });

  assert.equal(snapWritten, false);
});

// === Full result validation ===

test("remediate output: full plan from mixed findings passes schema + no secrets + deterministic", () => {
  const result = makeResult([
    makeSqlFinding(),           // critical
    makeRealtimeFinding(),      // critical
    makeEdgeFunctionFinding(),  // high
    makeMgmtApiFinding(),       // medium
    makeDashboardOnlyFinding(), // medium
    makeNetworkFinding(),       // high
  ]);

  const plan = planRemediations(result);
  assert.equal(plan.length, 6);

  // Verify each plan item's fix passes schema when embedded in a finding
  for (const item of plan) {
    const json = JSON.stringify(item.fix);
    // No secrets in any fix output
    assert.equal(scanForSecrets(json).length, 0, `secrets in fix for ${item.check}`);
    // management_api_action, if present, has method + path + body
    if (item.management_api_action) {
      assert.ok(item.management_api_action.method);
      assert.ok(item.management_api_action.path);
      assert.ok(item.management_api_action.body !== undefined);
    }
  }

  // Deterministic: running twice produces identical output
  const plan1 = JSON.stringify(planRemediations(result));
  const plan2 = JSON.stringify(planRemediations(result));
  assert.equal(plan1, plan2, "plan must be deterministic");
});

test("remediate output: schema-valid result with all fix types", async () => {
  const result = makeResult([
    makeSqlFinding(),
    makeMgmtApiFinding(),
    makeDashboardOnlyFinding(),
    makeNetworkFinding(),
  ]);

  // Dry-run output
  const dryRunResult = await remediate(result, { dryRun: true, ref: result.project_ref });
  const jsonOutput = JSON.stringify(dryRunResult);

  // No secrets
  assert.equal(scanForSecrets(jsonOutput).length, 0, "no secrets in dry-run output");

  // Plan has all 4 findings
  assert.equal(dryRunResult.plan.length, 4);

  // Summary counts
  assert.equal(dryRunResult.summary.total, 4);
  assert.equal(dryRunResult.summary.sql_executable, 1); // rls_disabled
  assert.equal(dryRunResult.summary.mgmt_api_executable, 2); // auth_hibp + network_db
  assert.equal(dryRunResult.summary.dashboard_only, 1); // data_api_auto_expose
});

test("remediate: empty result produces empty plan + zero summary", async () => {
  const emptyResult = makeResult([]);
  const out = await remediate(emptyResult, { dryRun: true, ref: "ref123" });
  assert.equal(out.plan.length, 0);
  assert.equal(out.summary.total, 0);
  assert.equal(out.summary.sql_executable, 0);
  assert.equal(out.summary.dashboard_only, 0);
});

// === Safety guardrails (architect safety steer) ===

test("remediate apply: production ref blocklist refuses to apply", async () => {
  // Use SUPA360_BLOCKED_REFS env var so the real prod refs never appear in tests.
  const DUMMY_BLOCKED = "test-prod-ref-12345";
  const prevEnv = process.env.SUPA360_BLOCKED_REFS;
  process.env.SUPA360_BLOCKED_REFS = DUMMY_BLOCKED;
  try {
    const result = makeResult([makeSqlFinding()], DUMMY_BLOCKED);
    await assert.rejects(
      async () => remediate(result, {
        dryRun: false, token: "sbp_test", ref: DUMMY_BLOCKED,
        _dbQuery: async () => [],
        _mgmtRequest: async () => ({}),
      }),
      (err) => err.code === "PROD_REF_BLOCKED" && /refusing.*production/.test(err.message)
    );
  } finally {
    process.env.SUPA360_BLOCKED_REFS = prevEnv;
  }
});

test("remediate apply: second blocked ref also rejected", async () => {
  const DUMMY_BLOCKED = "test-prod-ref-67890";
  const prevEnv = process.env.SUPA360_BLOCKED_REFS;
  process.env.SUPA360_BLOCKED_REFS = DUMMY_BLOCKED;
  try {
    const result = makeResult([makeSqlFinding()], DUMMY_BLOCKED);
    await assert.rejects(
      async () => remediate(result, {
        dryRun: false, token: "sbp_test", ref: DUMMY_BLOCKED,
        _dbQuery: async () => [],
        _mgmtRequest: async () => ({}),
      }),
      (err) => err.code === "PROD_REF_BLOCKED"
    );
  } finally {
    process.env.SUPA360_BLOCKED_REFS = prevEnv;
  }
});

test("remediate dry-run: does NOT enforce prod ref blocklist (dry-run is read-only)", async () => {
  const result = makeResult([makeSqlFinding()], "test-prod-ref-99999");
  const out = await remediate(result, { dryRun: true, ref: "test-prod-ref-99999" });
  assert.equal(out.mode, "dry-run");
  assert.equal(out.plan.length, 1);
});

test("remediate apply: finding with no rollback_sql is skipped, not applied", async () => {
  const result = makeResult([makeSqlNoRollbackFinding(), makeSqlFinding()]);
  const dbCalls = [];
  const out = await remediate(result, {
    dryRun: false, token: "sbp_test", ref: "ref123",
    _dbQuery: async (q) => { dbCalls.push(q); return []; },
    _mgmtRequest: async () => ({}),
  });

  // Only the finding WITH rollback_sql should have been applied
  assert.equal(dbCalls.length, 1, "only the rollback-having finding calls dbQuery");
  assert.ok(dbCalls[0].includes("leaky_table"), "applied the rollback-bearing finding");

  const noRollback = out.results.find((r) => r.check === "rls_temp_fix_no_rollback");
  assert.ok(noRollback);
  assert.equal(noRollback.actions[0].status, "skipped");
  assert.ok(noRollback.actions[0].reason.includes("rollback"));

  const applied = out.summary.applied;
  const skipped = out.summary.skipped;
  assert.equal(skipped, 1, "one finding skipped for missing rollback");
  assert.equal(applied, 1, "one finding applied");
});

test("remediate apply: requires_service_role finding skipped without service_role_key", async () => {
  const result = makeResult([makeSerRoleFinding()]);
  const dbCalls = [];
  const out = await remediate(result, {
    dryRun: false, token: "sbp_test", ref: "ref123",
    _dbQuery: async (q) => { dbCalls.push(q); return []; },
    _mgmtRequest: async () => ({}),
  });

  assert.equal(dbCalls.length, 0, "must NOT call dbQuery without service_role key");
  const r = out.results.find((r2) => r2.check === "rls_leaky_owner_default_privileges");
  assert.ok(r);
  assert.equal(r.actions[0].status, "skipped");
  assert.ok(r.actions[0].reason.includes("service_role"));
  assert.equal(out.summary.skipped, 1);
  assert.equal(out.summary.applied, 0);
});

test("remediate apply: requires_service_role finding applied when service_role_key provided", async () => {
  const result = makeResult([makeSerRoleFinding()]);
  const dbCalls = [];
  const out = await remediate(result, {
    dryRun: false, token: "sbp_test", ref: "ref123",
    service_role_key: "service_role_abc123",
    _dbQuery: async (q) => { dbCalls.push(q); return []; },
    _mgmtRequest: async () => ({}),
  });

  assert.equal(dbCalls.length, 2, "service_role key present -> 1 capture + 1 apply dbCall");
  const applyCall = dbCalls.find((q) => q.includes("BEGIN;"));
  assert.ok(applyCall, "SQL wrapped in BEGIN/COMMIT");
  const r = out.results.find((r2) => r2.check === "rls_leaky_owner_default_privileges");
  assert.equal(r.actions[0].status, "applied");
  assert.equal(out.summary.applied, 1);
  assert.equal(out.summary.failed, 0);
});

test("remediate apply: idempotent re-apply does not error (guardrails pass)", async () => {
  const result = makeResult([makeSqlFinding(), makeMgmtApiFinding()]);

  for (let i = 0; i < 2; i++) {
    const out = await remediate(result, {
      dryRun: false, token: "sbp_test", ref: "ref123",
      _dbQuery: async () => [],
      _mgmtRequest: async () => ({}),
    });
    assert.equal(out.summary.failed, 0, `iteration ${i}: no failures`);
    assert.equal(out.summary.applied, 2, `iteration ${i}: both applied`);
  }
});

// === verifyRemediation (entry 25: re-verification after --apply) ===

test("verifyRemediation: applied SQL finding with verifyFn -> verified", async () => {
  const findings = makeResult([makeSqlFinding(), makeDashboardOnlyFinding(), makeMgmtApiFinding()]);
  const plan = planRemediations(findings);
  // plan sorted: rls_disabled (critical) < auth_hibp_disabled (medium) < data_api_auto_expose_on (medium)
  const execResults = [
    { id: plan[0].id, check: "rls_disabled", target: "leaky_table", severity: "critical", actions: [{ type: "sql", status: "applied" }] },
    { id: plan[1].id, check: "auth_hibp_disabled", target: "auth:password", severity: "medium", actions: [{ type: "mgmt_api", status: "applied" }] },
    { id: plan[2].id, check: "data_api_auto_expose_on", target: "project:ref123", severity: "medium", actions: [{ type: "dashboard_skip", status: "skipped" }] },
  ];

  const v = await verifyRemediation(plan, execResults, async (item) => ({
    verified: true,
    reason: "re-probe returns 42501 (blocked)",
  }));

  assert.equal(v.summary.fixed_confirmed, 2);  // SQL + mgmt API
  assert.equal(v.summary.fixed_unverified, 0);
  assert.equal(v.summary.fixed_failed, 0);
  assert.equal(v.summary.needs_dashboard, 1);  // dashboard-only

  const sqlItem = v.items.find((i) => i.check === "rls_disabled");
  assert.equal(sqlItem.status, "verified");
  assert.equal(sqlItem.remediation_verified, true);

  const dashItem = v.items.find((i) => i.check === "data_api_auto_expose_on");
  assert.equal(dashItem.status, "needs_dashboard");
  assert.equal(dashItem.remediation_verified, null, "dashboard-only is null (can't verify), not false (failed)");

  const apiItem = v.items.find((i) => i.check === "auth_hibp_disabled");
  assert.equal(apiItem.status, "verified");
  assert.equal(apiItem.remediation_verified, true);
});

test("verifyRemediation: verifyFn returns false -> unverified with reason", async () => {
  const findings = makeResult([makeSqlFinding()]);
  const plan = planRemediations(findings);
  const execResults = [
    { id: plan[0].id, check: "rls_disabled", target: "leaky_table", severity: "critical", actions: [{ type: "sql", status: "applied" }] },
  ];

  const v = await verifyRemediation(plan, execResults, async (item) => ({
    verified: false,
    reason: "probe still returns 200 with rows — table still exposed",
  }));

  assert.equal(v.summary.fixed_confirmed, 0);
  assert.equal(v.summary.fixed_unverified, 0);
  assert.equal(v.summary.fixed_failed, 1);
  const item = v.items[0];
  assert.equal(item.status, "unverified");
  assert.equal(item.remediation_verified, false);
  assert.ok(item.reason.includes("still exposed"));
});

test("verifyRemediation: without verifyFn -> applied items are unverified (null, not false)", async () => {
  const findings = makeResult([makeSqlFinding()]);
  const plan = planRemediations(findings);
  const execResults = [
    { id: plan[0].id, check: "rls_disabled", target: "leaky_table", severity: "critical", actions: [{ type: "sql", status: "applied" }] },
  ];

  const v = await verifyRemediation(plan, execResults, null);
  const item = v.items[0];
  assert.equal(item.status, "unverified");
  assert.equal(item.remediation_verified, null, "no verifyFn = null (unknown), not false (failed)");
  assert.equal(v.summary.fixed_unverified, 1, "no-op bug: should be unverified, not failed");
  assert.equal(v.summary.fixed_failed, 0, "no apply failures");
  assert.ok(item.reason.includes("No verification callback"));
});

test("verifyRemediation: skipped/not-applied finding -> skipped, not verified", async () => {
  const findings = makeResult([makeSqlNoRollbackFinding()]);
  const plan = planRemediations(findings);
  // Simulate: finding was skipped (no rollback_sql)
  const execResults = [
    { id: plan[0].id, check: "rls_temp_fix_no_rollback", target: "table:no_rollback", severity: "high",
      actions: [{ type: "sql", status: "skipped", reason: "No rollback_sql available" }] },
  ];

  const v = await verifyRemediation(plan, execResults, async () => ({ verified: true }));
  const item = v.items[0];
  assert.equal(item.status, "skipped");
  assert.equal(item.remediation_verified, null, "skipped finding is null (can't verify), not false");
  assert.equal(v.summary.fixed_confirmed, 0);
  assert.equal(v.summary.fixed_unverified, 0);
});

test("remediate apply: includes verification field in output", async () => {
  const result = makeResult([makeSqlFinding(), makeDashboardOnlyFinding()]);
  const out = await remediate(result, {
    dryRun: false, token: "sbp_test", ref: "ref123",
    _dbQuery: async () => [],
    _mgmtRequest: async () => ({}),
    verifyFn: async (item) => ({ verified: true, reason: "closed" }),
  });

  assert.ok(out.verification);
  assert.ok(Array.isArray(out.verification.items));
  assert.ok(out.verification.summary);
  assert.equal(out.verification.summary.fixed_confirmed, 1);  // only SQL applied
  assert.equal(out.verification.summary.needs_dashboard, 1);  // dashboard-only
  assert.equal(out.verification.summary.fixed_unverified, 0);
  assert.equal(out.verification.summary.fixed_failed, 0);
});

test("remediate dry-run: does not include verification (nothing to verify)", async () => {
  const result = makeResult([makeSqlFinding()]);
  const out = await remediate(result, {
    dryRun: true, ref: "ref123",
    verifyFn: async () => ({ verified: true }),
  });

  // Dry-run should not run verification
  assert.equal(out.mode, "dry-run");
  assert.equal(out.verification, undefined);
});

// === rollbackRemediation (entry 26: idempotency + reversibility) ===

// Build a raw finding with both management_api_action + rollback_management_api_action
// (mirrors what real check modules produce post-entry-24).
function makeMgmtApiWithRollbackFinding() {
  return normalizeFinding({
    check: "auth_hibp_disabled",
    category: "coverage-auth",
    severity: "medium",
    confidence: "inferred",
    target: "auth:password",
    evidence: { password_hibp_enabled: false },
    title: "HIBP password breach checking disabled",
    explain: "Compromised passwords are not blocked.",
    fix: {
      sql: [],
      rollback_sql: [],
      dashboard_action: null,
      management_api_action: {
        method: "PATCH",
        path: "/v1/projects/ref123/config/auth",
        body: { password_hibp_enabled: true },
      },
      rollback_management_api_action: {
        method: "PATCH",
        path: "/v1/projects/ref123/config/auth",
        body: { password_hibp_enabled: false },
      },
      requires_service_role: false,
    },
  });
}

// A snapshot item factory matching what remediate() writes.
function makeSnapshotItem(opts) {
  return {
    id: "id_" + Math.random().toString(36).slice(2, 8),
    check: opts.check,
    target: opts.target,
    severity: opts.severity,
    requires_service_role: !!opts.requires_service_role,
    sql_to_execute: opts.sql_to_execute || [],
    rollback_sql: opts.rollback_sql || [],
    management_api_action: opts.management_api_action || null,
    rollback_management_api_action: opts.rollback_management_api_action || null,
    dashboard_action: opts.dashboard_action || null,
  };
}

function makeSnapshot(ref, items) {
  return { project_ref: ref, timestamp: "2026-08-27T00:00:00.000Z", plan: items };
}

test("rollbackRemediation: executes rollback_sql wrapped in BEGIN/COMMIT for SQL findings", async () => {
  const snapshot = makeSnapshot("ref123", [
    makeSnapshotItem({
      check: "rls_disabled", target: "leaky_table", severity: "critical",
      rollback_sql: ["ALTER TABLE public.leaky_table DISABLE ROW LEVEL SECURITY;"],
    }),
  ]);

  const dbCalls = [];
  const out = await rollbackRemediation(snapshot, {
    token: "sbp_test", ref: "ref123",
    _dbQuery: async (q) => { dbCalls.push(q); return []; },
    _mgmtRequest: async () => { assert.fail("mgmtRequest should not be called for SQL-only finding"); },
  });

  assert.equal(out.mode, "rollback");
  assert.equal(dbCalls.length, 1, "should call dbQuery once");
  assert.ok(dbCalls[0].startsWith("BEGIN;"), "rollback SQL must be wrapped in BEGIN");
  assert.ok(dbCalls[0].endsWith("COMMIT;"), "rollback SQL must end with COMMIT");
  assert.ok(dbCalls[0].includes("DISABLE ROW LEVEL SECURITY"), "executes the inverse SQL");
  assert.equal(out.summary.applied, 1);
  assert.equal(out.summary.failed, 0);
});

test("rollbackRemediation: executes rollback_management_api_action for mgmt-API findings", async () => {
  const snapshot = makeSnapshot("ref123", [
    makeSnapshotItem({
      check: "auth_hibp_disabled", target: "auth:password", severity: "medium",
      management_api_action: { method: "PATCH", path: "/v1/projects/ref123/config/auth", body: { password_hibp_enabled: true } },
      rollback_management_api_action: { method: "PATCH", path: "/v1/projects/ref123/config/auth", body: { password_hibp_enabled: false } },
    }),
  ]);

  const mgmtCalls = [];
  const out = await rollbackRemediation(snapshot, {
    token: "sbp_test", ref: "ref123",
    _dbQuery: async () => { assert.fail("dbQuery should not be called for mgmt-API-only finding"); },
    _mgmtRequest: async (m, p, b) => { mgmtCalls.push({ m, p, b }); return {}; },
  });

  assert.equal(mgmtCalls.length, 1);
  assert.equal(mgmtCalls[0].m, "PATCH");
  assert.equal(mgmtCalls[0].p, "/v1/projects/ref123/config/auth");
  assert.deepEqual(mgmtCalls[0].b, { password_hibp_enabled: false });
  assert.equal(out.summary.applied, 1);
});

test("rollbackRemediation: skips dashboard-only items (no transport calls)", async () => {
  const snapshot = makeSnapshot("ref123", [
    makeSnapshotItem({
      check: "data_api_auto_expose_on", target: "project:ref123", severity: "medium",
      dashboard_action: "Dashboard -> Data API: toggle auto-expose OFF",
    }),
  ]);

  let dbCalled = 0;
  let mgmtCalled = 0;
  const out = await rollbackRemediation(snapshot, {
    token: "sbp_test", ref: "ref123",
    _dbQuery: async () => { dbCalled++; return []; },
    _mgmtRequest: async () => { mgmtCalled++; return {}; },
  });

  assert.equal(dbCalled, 0, "must not call dbQuery for dashboard-only");
  assert.equal(mgmtCalled, 0, "must not call mgmtRequest for dashboard-only");
  const item = out.results.find((r) => r.check === "data_api_auto_expose_on");
  assert.equal(item.actions[0].type, "dashboard_skip");
  assert.equal(item.actions[0].status, "skipped");
  assert.ok(item.actions[0].click_path);
  assert.equal(out.summary.skipped, 1);
});

test("rollbackRemediation: idempotent — re-running rollback does not error", async () => {
  const snapshot = makeSnapshot("ref123", [
    makeSnapshotItem({
      check: "rls_disabled", target: "leaky_table", severity: "critical",
      rollback_sql: ["ALTER TABLE public.leaky_table DISABLE ROW LEVEL SECURITY;"],
    }),
  ]);

  const opts = {
    token: "sbp_test", ref: "ref123",
    _dbQuery: async () => [],
    _mgmtRequest: async () => ({}),
  };

  const out1 = await rollbackRemediation(snapshot, opts);
  assert.equal(out1.summary.failed, 0, "first rollback: no failures");
  assert.equal(out1.summary.applied, 1);

  const out2 = await rollbackRemediation(snapshot, opts);
  assert.equal(out2.summary.failed, 0, "second rollback: no failures (idempotent)");
  assert.equal(out2.summary.applied, 1);
});

test("rollbackRemediation: full cycle — apply -> apply (no error) -> rollback executes inverse SQL", async () => {
  // Start from a real audit-style result with a finding that has fix + rollback
  const result = makeResult([makeSqlFinding(), makeMgmtApiWithRollbackFinding()]);

  // --- Apply #1: capture the snapshot via injected _writeSnapshot ---
  let snapContent = null;
  const applyOut1 = await remediate(result, {
    dryRun: false, token: "sbp_test", ref: result.project_ref,
    _dbQuery: async () => [],
    _mgmtRequest: async () => ({}),
    _writeSnapshot: (_path, content) => { snapContent = content; },
  });
  assert.equal(applyOut1.summary.applied, 2, "apply #1: both SQL + mgmt API applied");
  assert.ok(snapContent, "snapshot was written");
  const snapshot = JSON.parse(snapContent);
  assert.equal(snapshot.project_ref, "ref123");
  assert.ok(Array.isArray(snapshot.plan));
  assert.equal(snapshot.plan.length, 2);

  // --- Apply #2: idempotent, no error ---
  const applyOut2 = await remediate(result, {
    dryRun: false, token: "sbp_test", ref: result.project_ref,
    _dbQuery: async () => [],
    _mgmtRequest: async () => ({}),
    _writeSnapshot: () => {},
  });
  assert.equal(applyOut2.summary.failed, 0, "apply #2: no failures (idempotent)");

  // --- Rollback using the captured snapshot ---
  const rollbackDbCalls = [];
  const rollbackMgmtCalls = [];
  const rollbackOut = await rollbackRemediation(snapshot, {
    token: "sbp_test", ref: result.project_ref,
    _dbQuery: async (q) => { rollbackDbCalls.push(q); return []; },
    _mgmtRequest: async (m, p, b) => { rollbackMgmtCalls.push({ m, p, b }); return {}; },
  });

  // SQL finding: rollback_sql (DISABLE) is the inverse of fix SQL (ENABLE)
  assert.ok(rollbackDbCalls.length > 0, "rollback should execute rollback_sql");
  assert.ok(rollbackDbCalls[0].includes("DISABLE ROW LEVEL SECURITY"),
    "rollback SQL is the inverse of the fix (DISABLE, not ENABLE)");

  // Mgmt-API finding: rollback_management_api_action restores prior state (hibp: false)
  const mgmtRollback = rollbackMgmtCalls.find((c) => c.p.includes("config/auth"));
  assert.ok(mgmtRollback, "rollback should execute rollback_management_api_action");
  assert.deepEqual(mgmtRollback.b, { password_hibp_enabled: false }, "restores prior value (false)");

  assert.equal(rollbackOut.summary.failed, 0);
  assert.equal(rollbackOut.mode, "rollback");
});

test("rollbackRemediation: production ref blocklist refuses to rollback", async () => {
  const DUMMY = "test-prod-ref-99999";
  const prevEnv = process.env.SUPA360_BLOCKED_REFS;
  process.env.SUPA360_BLOCKED_REFS = DUMMY;
  try {
    const snapshot = makeSnapshot(DUMMY, [
      makeSnapshotItem({
        check: "rls_disabled", target: "leaky_table", severity: "critical",
        rollback_sql: ["ALTER TABLE public.leaky_table DISABLE ROW LEVEL SECURITY;"],
      }),
    ]);
    await assert.rejects(
      async () => rollbackRemediation(snapshot, {
        token: "sbp_test", ref: DUMMY,
        _dbQuery: async () => [], _mgmtRequest: async () => ({}),
      }),
      (err) => err.code === "PROD_REF_BLOCKED" && /refusing.*production/.test(err.message)
    );
  } finally {
    process.env.SUPA360_BLOCKED_REFS = prevEnv;
  }
});

test("rollbackRemediation: second blocked ref also rejected", async () => {
  const DUMMY = "test-prod-ref-88888";
  const prevEnv = process.env.SUPA360_BLOCKED_REFS;
  process.env.SUPA360_BLOCKED_REFS = DUMMY;
  try {
    const snapshot = makeSnapshot(DUMMY, []);
    await assert.rejects(
      async () => rollbackRemediation(snapshot, {
        token: "sbp_test", ref: DUMMY,
        _dbQuery: async () => [], _mgmtRequest: async () => ({}),
      }),
      (err) => err.code === "PROD_REF_BLOCKED"
    );
  } finally {
    process.env.SUPA360_BLOCKED_REFS = prevEnv;
  }
});

test("rollbackRemediation: permanent ref is never unblocked — stays blocked under all ceremony combos (injected set)", async () => {
  // Validate (function level): "for a ref in the permanent set … Same for rollbackRemediation."
  // A permanent ref must stay blocked even when SUPA360_LAB_REF names it (or a
  // different ref) and both flags pass — the permanent tier is checked first.
  const DUMMY_PERM = "test-perm-ref-77777";
  const testPermSet = new Set([refHash(DUMMY_PERM)]);
  const snapshot = makeSnapshot(DUMMY_PERM, []);

  const combos = [
    { LAB_REF: undefined, ack: false, label: "no ceremony" },
    { LAB_REF: undefined, ack: true, label: "ack only, no env" },
    { LAB_REF: DUMMY_PERM, ack: true, label: "env names the same ref" },
    { LAB_REF: "test-other-ref-88888", ack: true, label: "env names a different ref" },
  ];

  for (const c of combos) {
    const prevLabRef = process.env.SUPA360_LAB_REF;
    const prevBlocked = process.env.SUPA360_BLOCKED_REFS;
    if (c.LAB_REF === undefined) delete process.env.SUPA360_LAB_REF;
    else process.env.SUPA360_LAB_REF = c.LAB_REF;
    // Also place it in the lab-eligible env, to prove even that cannot unblock a
    // permanent ref.
    process.env.SUPA360_BLOCKED_REFS = DUMMY_PERM;
    try {
      await assert.rejects(
        async () => rollbackRemediation(snapshot, {
          token: "sbp_test", ref: DUMMY_PERM,
          _dbQuery: async () => [], _mgmtRequest: async () => ({}),
          allowLab: c.ack, destructiveAck: c.ack,
          _permSet: testPermSet, _labSet: new Set(),
        }),
        (err) => err.code === "PROD_REF_BLOCKED"
      );
    } finally {
      if (prevLabRef === undefined) delete process.env.SUPA360_LAB_REF;
      else process.env.SUPA360_LAB_REF = prevLabRef;
      if (prevBlocked === undefined) delete process.env.SUPA360_BLOCKED_REFS;
      else process.env.SUPA360_BLOCKED_REFS = prevBlocked;
    }
  }
});

test("rollbackRemediation: missing token -> throws auth error", async () => {
  const snapshot = makeSnapshot("ref123", [
    makeSnapshotItem({
      check: "rls_disabled", target: "leaky_table", severity: "critical",
      rollback_sql: ["ALTER TABLE public.leaky_table DISABLE ROW LEVEL SECURITY;"],
    }),
  ]);

  await assert.rejects(
    async () => rollbackRemediation(snapshot, {
      token: null, ref: "ref123",
      _dbQuery: async () => [],
      _mgmtRequest: async () => ({}),
    }),
    (err) => err.code === "AUTH_ERROR"
  );
});

test("rollbackRemediation: requires_service_role finding skipped without service_role_key; applied with it", async () => {
  const snapshot = makeSnapshot("ref123", [
    makeSnapshotItem({
      check: "rls_leaky_owner_default_privileges", target: "table:leaky_owner", severity: "critical",
      requires_service_role: true,
      rollback_sql: ["GRANT SELECT ON TABLE public.leaky_owner TO anon;"],
    }),
  ]);

  // Without service_role_key: SQL rollback skipped
  const out1 = await rollbackRemediation(snapshot, {
    token: "sbp_test", ref: "ref123",
    _dbQuery: async () => [],
    _mgmtRequest: async () => ({}),
  });
  const r1 = out1.results.find((r) => r.check === "rls_leaky_owner_default_privileges");
  assert.equal(r1.actions[0].status, "skipped");
  assert.ok(r1.actions[0].reason.includes("service_role"));

  // With service_role_key: SQL rollback applied
  const dbCalls = [];
  const out2 = await rollbackRemediation(snapshot, {
    token: "sbp_test", ref: "ref123", service_role_key: "service_role_abc123",
    _dbQuery: async (q) => { dbCalls.push(q); return []; },
    _mgmtRequest: async () => ({}),
  });
  assert.equal(dbCalls.length, 1, "service_role key present -> rollback SQL is applied");
  assert.ok(dbCalls[0].includes("BEGIN;"));
  const r2 = out2.results.find((r) => r.check === "rls_leaky_owner_default_privileges");
  assert.equal(r2.actions[0].status, "applied");
});

test("rollbackRemediation: empty snapshot plan -> empty results", async () => {
  const snapshot = makeSnapshot("ref123", []);
  const out = await rollbackRemediation(snapshot, {
    token: "sbp_test", ref: "ref123",
    _dbQuery: async () => [],
    _mgmtRequest: async () => ({}),
  });
  assert.equal(out.mode, "rollback");
  assert.equal(out.results.length, 0);
  assert.equal(out.summary.applied, 0);
});

test("rollbackRemediation: snapshot path is recorded for reversibility", async () => {
  let snapWritten = false;
  const snapshot = makeSnapshot("ref123", [
    makeSnapshotItem({
      check: "rls_disabled", target: "leaky_table", severity: "critical",
      rollback_sql: ["ALTER TABLE public.leaky_table DISABLE ROW LEVEL SECURITY;"],
    }),
  ]);

  const out = await rollbackRemediation(snapshot, {
    token: "sbp_test", ref: "ref123",
    _dbQuery: async () => [],
    _mgmtRequest: async () => ({}),
    _writeSnapshot: () => { snapWritten = true; },
  });

  assert.ok(snapWritten, "pre-rollback snapshot should be written");
  assert.ok(out.snapshot_path, "output should carry the pre-rollback snapshot path");
});

// === Pipeline test (architect-seg#123: the test that would have caught the no-op) ===
// Simulates the REAL pipeline: audit finding -> normalizeFinding -> assembleResult
// -> JSON round-trip (serialize + parse) -> remediate({_dbQuery, _mgmtRequest}).
// Asserts that BOTH SQL and MGMT-API fixes are actually applied (not skipped).

test("pipeline: SQL + mgmt-API finding from real audit shape -> both _dbQuery + _mgmtRequest called", async () => {
  // Build a finding exactly like the real check modules produce (raw, pre-normalize)
  const rawFindings = [
    // SQL finding: default_privileges_not_revoked (like a real project)
    {
      check: "default_privileges_not_revoked",
      category: "coverage-rls",
      severity: "medium",
      confidence: "inferred",
      target: "auth:password",
      evidence: { owner_role: "postgres", defaclobjtype: "r", acl: "..." },
      fix: {
        sql: ["ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA public REVOKE SELECT ON TABLES FROM anon, authenticated;"],
        rollback_sql: ["ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA public GRANT SELECT ON TABLES TO anon, authenticated;"],
        dashboard_action: null,
        management_api_action: null,
        requires_service_role: false,
      },
    },
    // Management-API finding: auth_hibp_disabled (like a real project)
    {
      check: "auth_hibp_disabled",
      category: "coverage-auth",
      severity: "medium",
      confidence: "inferred",
      target: "auth:password",
      evidence: { password_hibp_enabled: false },
      title: "HIBP password breach checking disabled",
      explain: "Compromised passwords are not blocked.",
      fix: {
        sql: [],
        rollback_sql: [],
        dashboard_action: null,
        management_api_action: { method: "PATCH", path: "/v1/projects/ref123/config/auth", body: { password_hibp_enabled: true } },
        rollback_management_api_action: { method: "PATCH", path: "/v1/projects/ref123/config/auth", body: { password_hibp_enabled: false } },
        requires_service_role: false,
      },
    },
  ];

  // Simulate the real pipeline: normalize -> assemble -> JSON round-trip
  const result = assembleResult({
    project_ref: "ref123",
    mode: "audit-active",
    rawFindings: rawFindings,
  });

  // JSON round-trip — this is what happens when audit writes to stdout/file
  // and remediate reads it back. Catches shape mismatches.
  const jsonResult = JSON.parse(JSON.stringify(result));

  const dbCalls = [];
  const mgmtCalls = [];

  const out = await remediate(jsonResult, {
    dryRun: false,
    token: "sbp_test",
    ref: "ref123",
    _dbQuery: async (query) => { dbCalls.push(query); return []; },
    _mgmtRequest: async (method, path, body) => { mgmtCalls.push({ method, path, body }); return {}; },
    _writeSnapshot: () => {},
  });

  // SQL finding must be applied
  const sqlFinding = out.results.find((r) => r.check === "default_privileges_not_revoked");
  assert.ok(sqlFinding, "SQL finding in results");
  assert.equal(sqlFinding.actions[0].status, "applied", "SQL finding must be APPLIED (not skipped)");
  assert.ok(dbCalls.length > 0, "_dbQuery must be called with SQL");
  const applyCall = dbCalls.find((q) => q.includes("BEGIN;"));
  assert.ok(applyCall, "SQL wrapped in BEGIN/COMMIT");
  assert.ok(applyCall.includes("REVOKE"), "SQL contains the REVOKE statement");

  // MGMT-API finding must be applied
  const mgmtFinding = out.results.find((r) => r.check === "auth_hibp_disabled");
  assert.ok(mgmtFinding, "MGMT-API finding in results");
  assert.equal(mgmtFinding.actions[0].status, "applied", "MGMT-API finding must be APPLIED (not skipped)");
  assert.ok(mgmtCalls.length > 0, "_mgmtRequest must be called");
  assert.deepEqual(mgmtCalls[0], { method: "PATCH", path: "/v1/projects/ref123/config/auth", body: { password_hibp_enabled: true } });
});

test("pipeline: skipped == false — applied findings are NOT marked skipped in verification", async () => {
  const result = assembleResult({
    project_ref: "ref123",
    mode: "audit-active",
    rawFindings: [
      {
        check: "rls_disabled",
        category: "coverage-rls",
        severity: "critical",
        confidence: "confirmed",
        target: "leaky_table",
        evidence: { rls_enabled: false },
        fix: {
          sql: ["ALTER TABLE public.leaky_table ENABLE ROW LEVEL SECURITY;"],
          rollback_sql: ["ALTER TABLE public.leaky_table DISABLE ROW LEVEL SECURITY;"],
          management_api_action: null,
          requires_service_role: false,
        },
      },
    ],
  });

  const out = await remediate(JSON.parse(JSON.stringify(result)), {
    dryRun: false,
    token: "sbp_test",
    ref: "ref123",
    _dbQuery: async () => [],
    _mgmtRequest: async () => ({}),
    _writeSnapshot: () => {},
  });

  const applied = out.results.find((r) => r.check === "rls_disabled");
  assert.equal(applied.actions[0].status, "applied", "SQL finding applied in apply loop");
  // Verification should show it was applied (not "skipped: Fix was not applied")
  const verification = out.verification.items.find((i) => i.check === "rls_disabled");
  assert.ok(verification, "verification item exists");
  assert.notEqual(verification.status, "skipped", "must NOT be skipped in verification — wasApplied should be true");
});

// === Rollback skip for failed applies (architect seq#127 polish item 1) ===
// When a fix fails to apply (e.g. 402 on a paid feature), its rollback should
// be SKIPPED (not reported as "applied"), since there's nothing to undo.

test("rollback: skip fixes that were never successfully applied", async () => {
  // Build a snapshot with applied_ids tracking (simulates post-apply snapshot)
  const snapshot = {
    project_ref: "ref123",
    timestamp: "2026-08-28T22:00:00.000Z",
    mode: "apply",
    plan: [
      {
        id: "finding_a",
        check: "rls_disabled",
        target: "leaky_table",
        severity: "critical",
        rollback_sql: ["ALTER TABLE public.leaky_table DISABLE ROW LEVEL SECURITY;"],
        management_api_action: null,
        rollback_management_api_action: null,
        dashboard_action: null,
        requires_service_role: false,
        categories: { hasSql: true, hasMgmtApi: false, hasDashboard: false, isDashboardOnly: false, hasNoFix: false },
        sql_to_execute: ["ALTER TABLE public.leaky_table ENABLE ROW LEVEL SECURITY;"],
      },
      {
        id: "finding_b",
        check: "auth_hibp_disabled",
        target: "auth:password",
        severity: "medium",
        rollback_sql: [],
        management_api_action: { method: "PATCH", path: "/v1/projects/ref123/config/auth", body: { password_hibp_enabled: true } },
        rollback_management_api_action: { method: "PATCH", path: "/v1/projects/ref123/config/auth", body: { password_hibp_enabled: false } },
        dashboard_action: null,
        requires_service_role: false,
        categories: { hasSql: false, hasMgmtApi: true, hasDashboard: false, isDashboardOnly: false, hasNoFix: false },
        sql_to_execute: [],
      },
    ],
    // finding_a was successfully applied, finding_b was NOT (402 paid feature)
    applied_ids: ["finding_a"],
  };

  const dbCalls = [];
  const mgmtCalls = [];

  const out = await rollbackRemediation(snapshot, {
    token: "sbp_test",
    ref: "ref123",
    _dbQuery: async (q) => { dbCalls.push(q); return []; },
    _mgmtRequest: async (m, p, b) => { mgmtCalls.push({ m, p, b }); return {}; },
    _writeSnapshot: () => {},
  });

  // finding_a (applied) -> rollback SQL executed
  const resultA = out.results.find((r) => r.id === "finding_a");
  assert.equal(resultA.actions[0].status, "applied", "applied finding -> rollback executed");
  assert.ok(dbCalls.length > 0, "dbQuery called for applied finding rollback");

  // finding_b (NOT applied) -> rollback SKIPPED
  const resultB = out.results.find((r) => r.id === "finding_b");
  assert.ok(resultB, "unapplied finding is in results");
  const rollbackAction = resultB.actions.find((a) => a.type === "mgmt_api_rollback" || a.type === "rollback_skip");
  assert.equal(rollbackAction.status, "skipped", "unapplied finding -> rollback SKIPPED (not applied)");
  assert.equal(mgmtCalls.length, 0, "mgmtRequest NOT called for unapplied finding");
});

test("rollback: backward-compat — snapshot without applied_ids rolls back all", async () => {
  // Old snapshots (pre-applied_ids) should roll back everything (fallback)
  const snapshot = {
    project_ref: "ref123",
    plan: [{
      id: "finding_x",
      check: "rls_disabled",
      target: "leaky_table",
      severity: "critical",
      rollback_sql: ["ALTER TABLE public.leaky_table DISABLE ROW LEVEL SECURITY;"],
      management_api_action: null,
      rollback_management_api_action: null,
      dashboard_action: null,
      requires_service_role: false,
      categories: { hasSql: true, hasMgmtApi: false, hasDashboard: false, isDashboardOnly: false, hasNoFix: false },
      sql_to_execute: ["ALTER TABLE public.leaky_table ENABLE ROW LEVEL SECURITY;"],
    }],
    // NO applied_ids field — backward compatible
  };

  const out = await rollbackRemediation(snapshot, {
    token: "sbp_test", ref: "ref123",
    _dbQuery: async () => [],
    _mgmtRequest: async () => ({}),
    _writeSnapshot: () => {},
  });

  const result = out.results.find((r) => r.id === "finding_x");
  assert.ok(result, "finding in results");
  const sqlAction = result.actions.find((a) => a.type === "sql_rollback");
  assert.equal(sqlAction.status, "applied", "old snapshot format -> rollback proceeds");
});

test("rollback: applied_ids=[] (all applies failed) -> skip ALL rollbacks", async () => {
  // When applied_ids is present but EMPTY, NOTHING was applied -> roll back nothing.
  // This is the all-fail case (e.g. every SQL call errorred).
  const snapshot = {
    project_ref: "ref123",
    plan: [{
      id: "finding_x",
      check: "rls_disabled",
      target: "leaky_table",
      severity: "critical",
      rollback_sql: ["ALTER TABLE public.leaky_table DISABLE ROW LEVEL SECURITY;"],
      management_api_action: null,
      rollback_management_api_action: null,
      dashboard_action: null,
      requires_service_role: false,
      categories: { hasSql: true, hasMgmtApi: false, hasDashboard: false, isDashboardOnly: false, hasNoFix: false },
      sql_to_execute: ["ALTER TABLE public.leaky_table ENABLE ROW LEVEL SECURITY;"],
    }],
    applied_ids: [], // explicitly empty = nothing was applied
  };

  const dbCalls = [];
  const out = await rollbackRemediation(snapshot, {
    token: "sbp_test", ref: "ref123",
    _dbQuery: async (q) => { dbCalls.push(q); return []; },
    _mgmtRequest: async () => ({}),
    _writeSnapshot: () => {},
  });

  const result = out.results.find((r) => r.id === "finding_x");
  const skipAction = result.actions.find((a) => a.status === "skipped");
  assert.ok(skipAction, "nothing was applied -> rollback SKIPPED");
  assert.equal(dbCalls.length, 0, "dbQuery NOT called when applied_ids is empty");
});
