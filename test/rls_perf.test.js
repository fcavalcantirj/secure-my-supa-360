// Tests for scripts/checks/rls_perf.js (spec entry 36: unwrapped auth fn in policy)
import { test } from "node:test";
import assert from "node:assert/strict";
import { findUnwrappedAuthCalls, wrapAuthCalls, classifyPolicyPerf, processRlsPerf, extractPolicyColumns, classifyUnindexedPolicy, findJoinInPolicy, classifyJoinInPolicy, classifyPublicRoleTable } from "../scripts/checks/rls_perf.js";

// --- findUnwrappedAuthCalls ---

test("findUnwrappedAuthCalls: wrapped auth.uid() -> no unwrapped calls", () => {
  const calls = findUnwrappedAuthCalls("(select auth.uid()) = user_id");
  assert.equal(calls.length, 0);
});

test("findUnwrappedAuthCalls: unwrapped auth.uid() -> flagged", () => {
  const calls = findUnwrappedAuthCalls("auth.uid() = user_id");
  assert.equal(calls.length, 1);
  assert.equal(calls[0].name, "auth.uid()");
});

test("findUnwrappedAuthCalls: mixed wrapped + unwrapped -> only unwrapped flagged", () => {
  // auth.uid() is wrapped (safe), auth.role() is unwrapped (flag)
  const calls = findUnwrappedAuthCalls("(select auth.uid()) = user_id AND auth.role() = 'admin'");
  assert.equal(calls.length, 1);
  assert.equal(calls[0].name, "auth.role()");
});

test("findUnwrappedAuthCalls: multiple unwrapped calls -> all flagged", () => {
  const calls = findUnwrappedAuthCalls("auth.uid() = user_id AND auth.jwt() IS NOT NULL");
  assert.equal(calls.length, 2);
  assert.equal(calls[0].name, "auth.uid()");
  assert.equal(calls[1].name, "auth.jwt()");
});

test("findUnwrappedAuthCalls: current_setting unwrapped -> flagged", () => {
  const calls = findUnwrappedAuthCalls("current_setting('request.jwt.claim.sub') = user_id");
  assert.equal(calls.length, 1);
  assert.equal(calls[0].name, "current_setting(...)");
});

test("findUnwrappedAuthCalls: current_setting wrapped -> no calls", () => {
  const calls = findUnwrappedAuthCalls("(select current_setting('request.jwt.claim.sub')) = user_id");
  assert.equal(calls.length, 0);
});

test("findUnwrappedAuthCalls: case-insensitive auth.Uid() -> flagged", () => {
  const calls = findUnwrappedAuthCalls("Auth.Uid() = user_id");
  assert.equal(calls.length, 1);
});

test("findUnwrappedAuthCalls: null/empty expression -> no calls", () => {
  assert.deepEqual(findUnwrappedAuthCalls(null), []);
  assert.deepEqual(findUnwrappedAuthCalls(undefined), []);
  assert.deepEqual(findUnwrappedAuthCalls(""), []);
  assert.deepEqual(findUnwrappedAuthCalls(123), []);
});

test("findUnwrappedAuthCalls: policy with no auth calls -> clean", () => {
  const calls = findUnwrappedAuthCalls("user_id = 1 OR company_id IN (1,2,3)");
  assert.equal(calls.length, 0);
});

// --- wrapAuthCalls ---

test("wrapAuthCalls: unwrapped auth.uid() -> wrapped in (select ...)", () => {
  const fixed = wrapAuthCalls("auth.uid() = user_id");
  assert.equal(fixed, "(select auth.uid()) = user_id");
});

test("wrapAuthCalls: already-wrapped auth.uid() -> unchanged", () => {
  const fixed = wrapAuthCalls("(select auth.uid()) = user_id");
  assert.equal(fixed, "(select auth.uid()) = user_id");
});

test("wrapAuthCalls: mixed wrapped + unwrapped -> only unwrapped wrapped", () => {
  const fixed = wrapAuthCalls("(select auth.uid()) = user_id AND auth.role() = 'admin'");
  assert.equal(fixed, "(select auth.uid()) = user_id AND (select auth.role()) = 'admin'");
});

test("wrapAuthCalls: null/empty -> unchanged", () => {
  assert.equal(wrapAuthCalls(null), null);
  assert.equal(wrapAuthCalls(""), "");
});

test("wrapAuthCalls: multiple unwrapped calls -> all wrapped", () => {
  const fixed = wrapAuthCalls("auth.uid() = user_id AND auth.jwt() IS NOT NULL");
  assert.equal(fixed, "(select auth.uid()) = user_id AND (select auth.jwt()) IS NOT NULL");
});

// --- classifyPolicyPerf ---

test("classifyPolicyPerf: unwrapped auth.uid() in qual -> medium finding", () => {
  const policy = {
    policyname: "user_isolation",
    cmd: "ALL",
    roles: "{authenticated}",
    qual: "auth.uid() = user_id",
    with_check: null,
  };
  const f = classifyPolicyPerf(policy, "profiles");
  assert.ok(f, "expected a finding");
  assert.equal(f.check, "rls_unwrapped_auth_fn");
  assert.equal(f.severity, "medium");
  assert.equal(f.confidence, "inferred");
  assert.equal(f.category, "rls-performance");
  assert.equal(f.target, "policy:user_isolation on profiles");
  assert.equal(f.evidence.unwrapped_calls.length, 1);
  assert.equal(f.evidence.unwrapped_calls[0].name, "auth.uid()");
  assert.ok(f.fix.sql.length > 0);
  assert.equal(f.fix.requires_service_role, false);
});

test("classifyPolicyPerf: wrapped auth.uid() -> null (clean)", () => {
  const policy = {
    policyname: "safe_policy",
    cmd: "ALL",
    roles: "{authenticated}",
    qual: "(select auth.uid()) = user_id",
    with_check: "(select auth.uid()) = user_id",
  };
  const f = classifyPolicyPerf(policy, "profiles");
  assert.equal(f, null);
});

test("classifyPolicyPerf: null qual/with_check -> null (clean)", () => {
  const policy = {
    policyname: "permissive",
    cmd: "ALL",
    roles: "{public}",
    qual: null,
    with_check: null,
  };
  const f = classifyPolicyPerf(policy, "logs");
  assert.equal(f, null);
});

test("classifyPolicyPerf: fix.sql contains rewritten expression", () => {
  const policy = {
    policyname: "fn_policy",
    cmd: "SELECT",
    roles: "{authenticated}",
    qual: "auth.uid() = user_id",
    with_check: null,
  };
  const f = classifyPolicyPerf(policy, "orders");
  assert.ok(f.fix.sql.some((s) => s.includes("(select auth.uid())")));
});

// --- Entry 36: processRlsPerf ---

test("processRlsPerf: scans all policies across all tables", () => {
  const tables = [
    { table_name: "profiles", policies: [
      { policyname: "p1", cmd: "ALL", roles: "{authenticated}", qual: "auth.uid() = user_id", with_check: null },
      { policyname: "p2", cmd: "ALL", roles: "{authenticated}", qual: "(select auth.uid()) = user_id", with_check: null },
    ]},
    { table_name: "logs", policies: [
      { policyname: "p3", cmd: "SELECT", roles: "{authenticated}", qual: "true", with_check: null },
    ]},
  ];
  // user_id has a btree index on profiles, so entry 37 does NOT fire for p1
  const indexInfo = new Map([["profiles", ["user_id"]]]);
  const findings = processRlsPerf(tables, indexInfo);
  assert.equal(findings.length, 1, "only p1 has unwrapped auth call (p2 is wrapped, index protects p1's column)");
  assert.equal(findings[0].evidence.policy_name, "p1");
  assert.equal(findings[0].evidence.table_name, "profiles");
});

test("processRlsPerf: empty tables -> no findings", () => {
  assert.deepEqual(processRlsPerf([]), []);
  assert.deepEqual(processRlsPerf([{ table_name: "t", policies: [] }]), []);
});

// --- Entry 37: extractPolicyColumns ---

test("extractPolicyColumns: extracts bare column refs, strips parens/strings", () => {
  const cols = extractPolicyColumns("(select auth.uid()) = user_id AND company_id = 1");
  assert.ok(cols.includes("user_id"));
  assert.ok(cols.includes("company_id"));
  assert.ok(!cols.includes("auth"));
  assert.ok(!cols.includes("select"));
  assert.ok(!cols.includes("AND"));
});

test("extractPolicyColumns: null/empty -> empty", () => {
  assert.deepEqual(extractPolicyColumns(null), []);
  assert.deepEqual(extractPolicyColumns(""), []);
});

test("classifyUnindexedPolicy: column in equality with auth.fn, no index -> medium finding", () => {
  const policy = {
    policyname: "p1",
    cmd: "ALL",
    roles: "{authenticated}",
    qual: "(select auth.uid()) = user_id",
    with_check: null,
  };
  const f = classifyUnindexedPolicy(policy, "profiles", []); // no index on user_id
  assert.ok(f, "expected a finding");
  assert.equal(f.check, "rls_unindexed_policy_column");
  assert.equal(f.severity, "medium");
  assert.ok(f.evidence.columns.includes("user_id"));
  assert.ok(f.fix.sql.length > 0);
});

test("classifyUnindexedPolicy: column has btree index -> null", () => {
  const policy = {
    policyname: "p1",
    cmd: "ALL",
    roles: "{authenticated}",
    qual: "(select auth.uid()) = user_id",
    with_check: null,
  };
  const f = classifyUnindexedPolicy(policy, "profiles", ["user_id"]);
  assert.equal(f, null);
});

test("classifyUnindexedPolicy: no auth equality -> null", () => {
  const policy = {
    policyname: "p1",
    cmd: "ALL",
    roles: "{authenticated}",
    qual: "company_id = 1",
    with_check: null,
  };
  const f = classifyUnindexedPolicy(policy, "profiles", []);
  assert.equal(f, null, "non-auth equality is not flagged (conservative)");
});

test("classifyUnindexedPolicy: PK column in indexedColumns -> not flagged", () => {
  const policy = {
    policyname: "p1",
    cmd: "ALL",
    roles: "{authenticated}",
    qual: "(select auth.uid()) = id",
    with_check: null,
  };
  const f = classifyUnindexedPolicy(policy, "profiles", ["id"]); // 'id' is PK, indexed
  assert.equal(f, null, "PK column with btree index -> not flagged");
});

test("classifyUnindexedPolicy: subquery-internal column -> NOT attributed to outer table", () => {
  // (SELECT id FROM user_scope WHERE ...) = auth.uid() — 'id' is INSIDE the subquery
  const policy = {
    policyname: "p1",
    cmd: "SELECT",
    roles: "{authenticated}",
    qual: "(SELECT id FROM user_scope WHERE user_scope.id = profiles.id) = (select auth.uid())",
    with_check: null,
  };
  const f = classifyUnindexedPolicy(policy, "profiles", []);
  assert.equal(f, null, "subquery-internal 'id' is NOT attributed to outer table");
});

test("classifyUnindexedPolicy: direct equality on outer-table col, no index -> flagged", () => {
  // user_id IS the outer table's column, used directly in equality with auth.fn()
  const policy = {
    policyname: "p1",
    cmd: "ALL",
    roles: "{authenticated}",
    qual: "user_id = (select auth.uid())",
    with_check: null,
  };
  const f = classifyUnindexedPolicy(policy, "profiles", []); // user_id NOT indexed
  assert.ok(f, "expected a finding for unindexed outer-table column");
  assert.ok(f.evidence.columns.includes("user_id"));
  // Must NOT include 'id' from any subquery
  assert.ok(!f.evidence.columns.includes("id"), "subquery columns must not appear");
});

test("classifyUnindexedPolicy: get_my_company_id() equality -> column flagged", () => {
  // divergent-grantee pattern: company_id = get_my_company_id() (custom auth-derived fn)
  const policy = {
    policyname: "p1",
    cmd: "ALL",
    roles: "{authenticated}",
    qual: "company_id = get_my_company_id()",
    with_check: null,
  };
  const f = classifyUnindexedPolicy(policy, "documents", []);
  assert.ok(f, "expected a finding for unindexed company_id");
  assert.ok(f.evidence.columns.includes("company_id"));
});

test("classifyUnindexedPolicy: outer-paren expression -> column still matched", () => {
  // Outer parentheses wrapping the expression must NOT prevent detection.
  // (user_id = (select auth.uid())) — user_id is at depth 0 after stripSubqueries
  const policy = {
    policyname: "p1",
    cmd: "ALL",
    roles: "{authenticated}",
    qual: "(user_id = (select auth.uid()))",
    with_check: null,
  };
  const f = classifyUnindexedPolicy(policy, "profiles", []); // user_id NOT indexed
  assert.ok(f, "outer-paren expression must still flag unindexed column");
  assert.ok(f.evidence.columns.includes("user_id"));
});

// --- Entry 38: findJoinInPolicy / classifyJoinInPolicy ---

test("findJoinInPolicy: detects EXISTS", () => {
  const joins = findJoinInPolicy("EXISTS (SELECT 1 FROM team_user WHERE team_user.user_id = auth.uid())");
  assert.equal(joins.length, 1);
  assert.equal(joins[0].type, "exists");
});

test("findJoinInPolicy: detects correlated IN", () => {
  const joins = findJoinInPolicy("team_id IN (SELECT team_id FROM team_user WHERE user_id = (select auth.uid()))");
  assert.equal(joins.length, 1);
  assert.equal(joins[0].type, "in_subquery");
  assert.equal(joins[0].column, "team_id");
});

test("findJoinInPolicy: simple equality -> no joins", () => {
  const joins = findJoinInPolicy("user_id = (select auth.uid())");
  assert.equal(joins.length, 0);
});

test("classifyJoinInPolicy: EXISTS in qual -> medium finding", () => {
  const policy = {
    policyname: "team_scope",
    cmd: "ALL",
    roles: "{authenticated}",
    qual: "EXISTS (SELECT 1 FROM team_members WHERE team_members.user_id = (select auth.uid()))",
    with_check: null,
  };
  const f = classifyJoinInPolicy(policy, "documents");
  assert.ok(f, "expected a finding");
  assert.equal(f.check, "rls_policy_join");
  assert.equal(f.severity, "medium");
  assert.ok(f.fix.sql.length > 0);
});

test("classifyJoinInPolicy: clean policy -> null", () => {
  const policy = {
    policyname: "simple",
    cmd: "ALL",
    roles: "{authenticated}",
    qual: "(select auth.uid()) = user_id",
    with_check: null,
  };
  const f = classifyJoinInPolicy(policy, "profiles");
  assert.equal(f, null);
});

// --- Entry 39: classifyPublicRoleTable (aggregated per table) ---

test("classifyPublicRoleTable: roles={public} on 3 policies -> ONE finding, not 3", () => {
  const policies = [
    { policyname: "p1", cmd: "SELECT", roles: "{public}", qual: "true", with_check: null },
    { policyname: "p2", cmd: "ALL", roles: "{public,authenticated}", qual: "true", with_check: null },
    { policyname: "p3", cmd: "SELECT", roles: "{public}", qual: "true", with_check: null },
  ];
  const f = classifyPublicRoleTable("logs", policies);
  assert.ok(f, "expected a finding");
  assert.equal(f.check, "rls_policy_public_role");
  assert.equal(f.severity, "low");
  assert.equal(f.target, "table:logs");
  assert.equal(f.evidence.policy_count, 3);
  assert.equal(f.evidence.public_role_policies.length, 3);
  assert.ok(f.fix.sql.length > 0);
});

test("classifyPublicRoleTable: empty public policies (non-public roles) -> null", () => {
  // Caller (processRlsPerf) pre-filters to public-role policies only.
  // A table with only {authenticated} policies passes an empty array -> null.
  const f = classifyPublicRoleTable("profiles", []);
  assert.equal(f, null);
});

test("classifyPublicRoleTable: roles as JS array (sqlBatched shape) -> does not crash", () => {
  const policies = [
    { policyname: "p1", cmd: "ALL", roles: ["public", "authenticated"], qual: "true", with_check: null },
    { policyname: "p2", cmd: "SELECT", roles: ["public"], qual: "true", with_check: null },
  ];
  const f = classifyPublicRoleTable("logs", policies);
  assert.ok(f, "expected a finding");
  assert.equal(f.evidence.policy_count, 2);
  assert.ok(f.fix.rollback_sql.some((s) => s.includes("TO public, authenticated")), "rollback uses joined array roles");
});

test("classifyPublicRoleTable: empty policies -> null", () => {
  assert.equal(classifyPublicRoleTable("t", []), null);
  assert.equal(classifyPublicRoleTable("t", null), null);
});

// --- Regression: roles as JS array (sqlBatched returns pg_policies.roles as array) ---

test("classifyPolicyPerf: roles as array (sqlBatched shape) -> does not crash", () => {
  const policy = {
    policyname: "p1",
    cmd: "ALL",
    roles: ["authenticated"], // sqlBatched returns text[] as JS array
    qual: "auth.uid() = user_id",
    with_check: null,
  };
  const f = classifyPolicyPerf(policy, "profiles");
  assert.ok(f, "expected a finding");
  assert.equal(f.evidence.unwrapped_calls[0].name, "auth.uid()");
  assert.ok(f.fix.sql.some((s) => s.includes("TO authenticated")), "fix SQL uses joined role names");
});

test("classifyPublicRoleTable: roles as JS array (sqlBatched shape) -> does not crash", () => {
  const policies = [
    { policyname: "public_read", cmd: "SELECT", roles: ["public"], qual: "true", with_check: null },
  ];
  const f = classifyPublicRoleTable("logs", policies);
  assert.ok(f, "expected a finding");
  assert.equal(f.evidence.policy_count, 1);
  assert.ok(f.fix.rollback_sql.some((s) => s.includes("TO public")), "rollback restores public role");
});

test("processRlsPerf: roles as array on divergent-grantee policy -> finding (not crash)", () => {
  const tables = [
    { table_name: "documents", policies: [
      { policyname: "tenant_isolation", cmd: "ALL", roles: ["authenticated"], qual: "(select auth.uid()) = user_id", with_check: "(select auth.uid()) = user_id" },
    ]},
  ];
  // user_id has a btree index -> no unindexed finding; auth calls are wrapped -> no unwrapped finding
  const indexInfo = new Map([["documents", ["user_id"]]]);
  const findings = processRlsPerf(tables, indexInfo);
  assert.equal(findings.length, 0, "wrapped auth.uid + indexed column -> no findings");
});

