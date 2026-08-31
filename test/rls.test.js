import { test } from "node:test";
import assert from "node:assert/strict";
import {
  classifyTable,
  processTables,
  isPermissive,
  hasTenantScope,
  probeConfirmsLeak,
} from "../scripts/checks/rls.js";

test("isPermissive detects USING(true) variants", () => {
  assert.equal(isPermissive("true"), true);
  assert.equal(isPermissive("(true)"), true);
  assert.equal(isPermissive(" TRUE "), true);
  assert.equal(isPermissive("(user_id = auth.uid())"), false);
  assert.equal(isPermissive(null), false);
});

test("hasTenantScope recognizes caller-scoping expressions", () => {
  assert.equal(hasTenantScope("(user_id = auth.uid())"), true);
  assert.equal(hasTenantScope("(company_id = get_my_company_id())"), true);
  assert.equal(hasTenantScope("(true)"), false);
  assert.equal(hasTenantScope(null), false);
});

test("probeConfirmsLeak only on 200 + rows", () => {
  assert.equal(probeConfirmsLeak({ status: 200, rowCount: 3 }), true);
  assert.equal(probeConfirmsLeak({ status: 200, rowCount: 0 }), false);
  assert.equal(probeConfirmsLeak({ status: 401, rowCount: 0 }), false);
  assert.equal(probeConfirmsLeak(null), false);
});

// THE leaky table: RLS enabled + one `ALL USING (true)` policy + anon grants.
// Old audit.js produced NO finding. This MUST now flag, and the live probe
// (200 + rows) MUST mark it confirmed.
test("leaky table: RLS on + USING(true) policy + anon read + probe rows -> confirmed leak", () => {
  const table = {
    table_name: "sensitive_photos",
    rls_enabled: true,
    policies: [
      { policyname: "Allow public access to sensitive_photos", cmd: "ALL", roles: "{public}", qual: "true", with_check: null },
    ],
    anon_select: true,
    sensitive_columns: ["patient_cpf"],
  };
  const f = classifyTable(table, { status: 200, rowCount: 1 });
  assert.ok(f, "expected a finding");
  assert.equal(f.check, "rls_permissive_policy");
  assert.equal(f.confidence, "confirmed");
  assert.equal(f.severity, "critical"); // escalated: sensitive column + confirmed
});

test("same policy but anon actually blocked (probe 42501) -> inferred, not confirmed", () => {
  const table = {
    table_name: "sensitive_photos",
    rls_enabled: true,
    policies: [{ policyname: "p", cmd: "SELECT", roles: "{authenticated}", qual: "true" }],
    auth_select: true,
    anon_select: false,
  };
  const f = classifyTable(table, { status: 401, rowCount: 0 });
  assert.ok(f);
  assert.equal(f.check, "rls_permissive_policy");
  assert.equal(f.confidence, "inferred");
  assert.equal(f.severity, "high");
});

test("RLS disabled + anon grant -> critical", () => {
  const f = classifyTable(
    { table_name: "leaky", rls_enabled: false, policies: [], anon_select: true },
    { status: 200, rowCount: 9 }
  );
  assert.equal(f.check, "rls_disabled");
  assert.equal(f.confidence, "confirmed");
});

test("RLS on, zero policies, anon grant -> low defense-in-depth", () => {
  const f = classifyTable(
    { table_name: "locked", rls_enabled: true, policies: [], anon_select: true },
    { status: 401, rowCount: 0 }
  );
  assert.equal(f.check, "rls_no_policies_with_anon_grants");
  assert.equal(f.severity, "low");
});

test("properly scoped policy -> no finding (no false positive)", () => {
  const table = {
    table_name: "orders",
    rls_enabled: true,
    policies: [
      { policyname: "own", cmd: "SELECT", roles: "{authenticated}", qual: "(user_id = auth.uid())" },
    ],
    auth_select: true,
  };
  assert.equal(classifyTable(table, { status: 200, rowCount: 0 }), null);
});

test("safe: RLS on, no policies, no grants -> null", () => {
  assert.equal(
    classifyTable({ table_name: "x", rls_enabled: true, policies: [], anon_select: false, auth_select: false }, null),
    null
  );
});

test("processTables: the leak row -> confirmed rls_permissive_policy; scoped row -> no finding", async () => {
  const rows = [
    {
      table_name: "sensitive_photos",
      rls_enabled: true,
      policies: [
        { policyname: "Allow public access to sensitive_photos", cmd: "ALL", roles: "{public}", qual: "true", with_check: null },
      ],
      anon_select: true,
      anon_insert: false,
      anon_delete: false,
      auth_select: false,
    },
    {
      table_name: "orders",
      rls_enabled: true,
      policies: [
        { policyname: "own", cmd: "SELECT", roles: "{authenticated}", qual: "(user_id = auth.uid())", with_check: null },
      ],
      anon_select: false,
      anon_insert: false,
      anon_delete: false,
      auth_select: true,
    },
  ];
  // fake async probeFn: anon probe returns 200 + 1 row for sensitive_photos, 401 blocked for others
  const probeFn = async (tableName) => {
    if (tableName === "sensitive_photos") return { status: 200, rowCount: 1 };
    return { status: 401, rowCount: 0 };
  };
  const findings = await processTables(rows, probeFn);
  const checks = findings.map((f) => `${f.check}:${f.target}:${f.confidence}:${f.severity}`);

  const pp = findings.find((f) => f.check === "rls_permissive_policy");
  assert.ok(pp, `expected rls_permissive_policy — got: ${checks.length ? checks.join(", ") : "none"}`);
  assert.equal(pp.target, "sensitive_photos");
  assert.equal(pp.confidence, "confirmed");
  assert.equal(pp.severity, "high");
  // scoped policy -> NOT flagged (no false positive)
  assert.equal(
    findings.find((f) => f.target === "orders"),
    undefined,
    `orders should not be flagged — got: ${checks.join(", ")}`
  );
});

test("processTables: no probeFn -> confidence stays 'inferred'", async () => {
  const rows = [
    {
      table_name: "sensitive_photos",
      rls_enabled: true,
      policies: [{ policyname: "p", cmd: "ALL", roles: "{public}", qual: "true", with_check: null }],
      anon_select: true,
      anon_insert: false,
      anon_delete: false,
      auth_select: false,
    },
  ];
  const findings = await processTables(rows, null);
  assert.equal(findings.length, 1);
  assert.equal(findings[0].check, "rls_permissive_policy");
  assert.equal(findings[0].confidence, "inferred");
});

test("INSERT policy with permissive WITH CHECK + anon grant -> rls_permissive_write_policy (high, confirmed)", () => {
  const table = {
    table_name: "comments",
    rls_enabled: true,
    policies: [
      { policyname: "allow_anon_insert", cmd: "INSERT", roles: "{anon}", qual: null, with_check: "true" },
    ],
    anon_select: false,
    anon_insert: true,
    anon_delete: false,
    auth_select: false,
    sensitive_columns: [],
  };
  const f = classifyTable(table, { status: 200, rowCount: 1, bytes: 128 });
  assert.ok(f, "expected a write-side finding");
  assert.equal(f.check, "rls_permissive_write_policy");
  assert.equal(f.confidence, "confirmed");
  assert.equal(f.severity, "high");
  assert.equal(f.evidence.probe.bytes, 128);
  assert.equal(f.evidence.probe.row_count, 1);
});

test("INSERT policy with NULL WITH CHECK + anon grant -> rls_permissive_write_policy (missing guard)", () => {
  const table = {
    table_name: "raw_inserts",
    rls_enabled: true,
    policies: [
      { policyname: "anon_write", cmd: "INSERT", roles: "{anon}", qual: null, with_check: null },
    ],
    anon_select: false,
    anon_insert: true,
    anon_delete: false,
    auth_select: false,
  };
  const f = classifyTable(table, null);
  assert.ok(f);
  assert.equal(f.check, "rls_permissive_write_policy");
  assert.equal(f.confidence, "inferred");
  assert.equal(f.severity, "high");
  assert.equal(f.details.reason, "policy has no WITH CHECK guard (writes unconstrained)");
});

test("UPDATE policy with divergent USING vs WITH CHECK -> rls_with_check_divergence (medium)", () => {
  const table = {
    table_name: "tickets",
    rls_enabled: true,
    policies: [
      { policyname: "scoped_update", cmd: "UPDATE", roles: "{authenticated}", qual: "(user_id = auth.uid())", with_check: "(user_id = auth.uid() OR is_admin())" },
    ],
    anon_select: false,
    anon_insert: false,
    anon_delete: false,
    auth_select: true,
  };
  const f = classifyTable(table, { status: 200, rowCount: 0 });
  assert.ok(f, "expected a divergence finding");
  assert.equal(f.check, "rls_with_check_divergence");
  assert.equal(f.severity, "medium");
  assert.equal(f.confidence, "inferred");
});

test("properly scoped INSERT policy (caller-scoped WITH CHECK) -> no write finding", () => {
  const table = {
    table_name: "own_comments",
    rls_enabled: true,
    policies: [
      { policyname: "own_write", cmd: "INSERT", roles: "{public}", qual: null, with_check: "(user_id = auth.uid())" },
    ],
    anon_select: false,
    anon_insert: true,
    anon_delete: false,
    auth_select: false,
  };
  assert.equal(classifyTable(table, { status: 200, rowCount: 0 }), null);
});

test("processTables: threads probe.bytes into evidence.probe", async () => {
  const rows = [
    {
      table_name: "secret_data",
      rls_enabled: false,
      policies: [],
      anon_select: true,
      anon_insert: false,
      anon_delete: false,
      auth_select: false,
    },
  ];
  const probeFn = async () => ({ status: 200, rowCount: 5, bytes: 512 });
  const [f] = await processTables(rows, probeFn);
  assert.equal(f.evidence.probe.status, 200);
  assert.equal(f.evidence.probe.row_count, 5);
  assert.equal(f.evidence.probe.bytes, 512);
});
