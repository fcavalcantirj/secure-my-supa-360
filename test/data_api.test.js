import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { classifyDataApiConfig, processDataApi } from "../scripts/checks/data_api.js";
import { normalizeFinding, assembleResult, scanForSecrets } from "../scripts/contract.js";
import { validate } from "../scripts/validate.js";

const SCHEMA_PATH = fileURLToPath(new URL("../schema/finding.schema.json", import.meta.url));
const schema = JSON.parse(readFileSync(SCHEMA_PATH, "utf8"));

// ---------------------------------------------------------------------------
// classifyDataApiConfig — auto_expose
// ---------------------------------------------------------------------------

test("classifyDataApiConfig: auto_expose ON with supabase_admin -> data_api_auto_expose_on (medium)", () => {
  const f = classifyDataApiConfig({
    auto_expose: true,
    leaky_owner_roles: ["supabase_admin"],
    exposed_schemas: ["public"],
    table_count: 5,
    function_count: 3,
  }, "ref123");
  assert.equal(f.length, 1);
  const finding = f[0];
  assert.equal(finding.check, "data_api_auto_expose_on");
  assert.equal(finding.severity, "medium");
  assert.equal(finding.confidence, "inferred");
  assert.equal(finding.target, "project:ref123");
  assert.equal(finding.evidence.auto_expose, true);
  assert.equal(finding.evidence.supabase_admin_default_privs, true);
  assert.equal(finding.evidence.exposed_table_count, 5);
  assert.equal(finding.evidence.exposed_function_count, 3);
  // SQL fix should only contain comments for supabase_admin (dashboard-only)
  assert.ok(finding.fix.sql.every((s) => s.trim().startsWith("--")), "supabase_admin-only should have no executable SQL");
  assert.ok(finding.fix.dashboard_action);
});

test("classifyDataApiConfig: auto_expose ON with postgres only -> SQL fix present", () => {
  const f = classifyDataApiConfig({
    auto_expose: true,
    leaky_owner_roles: ["postgres"],
    exposed_schemas: ["public"],
    table_count: 0,
    function_count: 0,
  }, "ref");
  assert.equal(f.length, 1);
  assert.equal(f[0].evidence.supabase_admin_default_privs, false);
  assert.ok(f[0].fix.sql.length > 0, "postgres owner should have SQL fix");
});

test("classifyDataApiConfig: auto_expose ON with both owners -> both SQL + dashboard", () => {
  const f = classifyDataApiConfig({
    auto_expose: true,
    leaky_owner_roles: ["postgres", "supabase_admin"],
    exposed_schemas: ["public"],
    table_count: 3,
    function_count: 2,
  }, "ref");
  assert.equal(f.length, 1);
  assert.ok(f[0].fix.sql.length > 0, "should have SQL for postgres");
  assert.ok(f[0].fix.dashboard_action, "should have dashboard action for supabase_admin");
});

test("classifyDataApiConfig: auto_expose OFF -> no finding", () => {
  assert.deepEqual(
    classifyDataApiConfig({
      auto_expose: false,
      leaky_owner_roles: [],
      exposed_schemas: ["public"],
      table_count: 3,
      function_count: 1,
    }, "ref"),
    []
  );
});

test("classifyDataApiConfig: null/undefined -> []", () => {
  assert.deepEqual(classifyDataApiConfig(null, "ref"), []);
  assert.deepEqual(classifyDataApiConfig(undefined, "ref"), []);
  assert.deepEqual(classifyDataApiConfig({ auto_expose: true }, "ref"), []);
});

// ---------------------------------------------------------------------------
// classifyDataApiConfig — function count
// ---------------------------------------------------------------------------

test("classifyDataApiConfig: many functions (>=20) -> data_api_many_functions_exposed (low)", () => {
  const f = classifyDataApiConfig({
    auto_expose: false,
    leaky_owner_roles: [],
    exposed_schemas: ["public"],
    table_count: 0,
    function_count: 96,
  }, "ref");
  assert.equal(f.length, 1);
  assert.equal(f[0].check, "data_api_many_functions_exposed");
  assert.equal(f[0].severity, "low");
  assert.equal(f[0].confidence, "confirmed");
  assert.equal(f[0].evidence.exposed_function_count, 96);
});

test("classifyDataApiConfig: few functions (<20) -> no function-count finding", () => {
  assert.deepEqual(
    classifyDataApiConfig({
      auto_expose: false,
      leaky_owner_roles: [],
      exposed_schemas: ["public"],
      table_count: 1,
      function_count: 5,
    }, "ref"),
    []
  );
});

test("classifyDataApiConfig: both auto_expose + many functions -> two findings", () => {
  const f = classifyDataApiConfig({
    auto_expose: true,
    leaky_owner_roles: ["supabase_admin"],
    exposed_schemas: ["public"],
    table_count: 10,
    function_count: 25,
  }, "ref");
  assert.equal(f.length, 2);
  const checks = f.map((x) => x.check).sort();
  assert.deepEqual(checks, ["data_api_auto_expose_on", "data_api_many_functions_exposed"]);
});

// ---------------------------------------------------------------------------
// processDataApi
// ---------------------------------------------------------------------------

test("processDataApi delegates to classifyDataApiConfig", () => {
  const result = processDataApi(
    { auto_expose: true, leaky_owner_roles: ["postgres"], exposed_schemas: ["public"], table_count: 1, function_count: 1 },
    "ref"
  );
  assert.equal(result.length, 1);
  assert.equal(result[0].check, "data_api_auto_expose_on");
});

// ---------------------------------------------------------------------------
// Round-trip: normalize -> assembleResult -> schema valid + no secrets + deterministic
// ---------------------------------------------------------------------------

test("data_api findings round-trip: normalize -> assembleResult -> schema valid + no secrets + deterministic", () => {
  const data = {
    auto_expose: true,
    leaky_owner_roles: ["supabase_admin"],
    exposed_schemas: ["public"],
    table_count: 5,
    function_count: 96,
  };
  const rawFindings = processDataApi(data, "xyz789");
  const normalized = rawFindings.map(normalizeFinding);

  const fixedAt = "2026-08-07T12:00:00.000Z";
  const opts = {
    project_ref: "xyz789",
    mode: "audit-active",
    rawFindings: normalized,
    generated_at: fixedAt,
  };
  const result = assembleResult(opts);

  // 1. Schema validation
  const { valid, errors } = validate(result, schema);
  assert.equal(valid, true, `schema violations: ${JSON.stringify(errors)}`);

  // 2. No secrets in output
  const jsonStr = JSON.stringify(result);
  assert.equal(scanForSecrets(jsonStr).length, 0, "secrets leaked in output");

  // 3. Deterministic ordering
  const json1 = JSON.stringify(assembleResult(opts), null, 2);
  const json2 = JSON.stringify(assembleResult(opts), null, 2);
  assert.equal(json1, json2, "output must be deterministic");

  // Verify findings
  assert.equal(result.findings.length, 2);
  const checks = result.findings.map((f) => f.check).sort();
  assert.deepEqual(checks, ["data_api_auto_expose_on", "data_api_many_functions_exposed"]);
});
