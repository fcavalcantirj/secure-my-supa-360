import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import {
  isSensitiveColumn,
  classifyColumnGrant,
  findExposedSchemas,
  processColumnGrants,
} from "../scripts/checks/grants.js";
import { normalizeFinding, assembleResult, scanForSecrets } from "../scripts/contract.js";
import { validate } from "../scripts/validate.js";

const SCHEMA_PATH = fileURLToPath(new URL("../schema/finding.schema.json", import.meta.url));
const schema = JSON.parse(readFileSync(SCHEMA_PATH, "utf8"));

// ---------------------------------------------------------------------------
// isSensitiveColumn
// ---------------------------------------------------------------------------

test("isSensitiveColumn: PII/credential column names are sensitive", () => {
  assert.equal(isSensitiveColumn("email"), true);
  assert.equal(isSensitiveColumn("cpf"), true);
  assert.equal(isSensitiveColumn("cnpj"), true);
  assert.equal(isSensitiveColumn("phone_number"), true);
  assert.equal(isSensitiveColumn("password"), true);
  assert.equal(isSensitiveColumn("api_key"), true);
  assert.equal(isSensitiveColumn("session_token"), true);
  assert.equal(isSensitiveColumn("birthdate"), true);
  assert.equal(isSensitiveColumn("health_record"), true);
});

test("isSensitiveColumn: non-sensitive column names are safe", () => {
  assert.equal(isSensitiveColumn("id"), false);
  assert.equal(isSensitiveColumn("name"), false);
  assert.equal(isSensitiveColumn("created_at"), false);
  assert.equal(isSensitiveColumn("updated_at"), false);
  assert.equal(isSensitiveColumn("is_active"), false);
  assert.equal(isSensitiveColumn("profile"), false);
  assert.equal(isSensitiveColumn(null), false);
  assert.equal(isSensitiveColumn(undefined), false);
  assert.equal(isSensitiveColumn(""), false);
});

test("isSensitiveColumn: data type heuristic (e.g. jsonb storing secrets)", () => {
  assert.equal(isSensitiveColumn("notes", "text"), false);
  assert.equal(isSensitiveColumn("config", "jsonb"), false);
  assert.equal(isSensitiveColumn("token", "text"), true);
});

// ---------------------------------------------------------------------------
// classifyColumnGrant
// ---------------------------------------------------------------------------

const GRANT_ROW = (overrides = {}) => ({
  schema_name: "public",
  table_name: "users",
  column_name: "email",
  data_type: "text",
  anon_col_select: true,
  auth_col_select: false,
  anon_table_select: false,
  auth_table_select: false,
  ...overrides,
});

test("classifyColumnGrant: sensitive column + table locked + anon col_select -> critical, confirmed bypass", () => {
  const f = classifyColumnGrant(GRANT_ROW());
  assert.ok(f, "expected a finding");
  assert.equal(f.check, "column_grant_exposes_column");
  assert.equal(f.severity, "critical");
  assert.equal(f.confidence, "inferred");
  assert.equal(f.target, "column:schema:public:table:users:col:email");
  assert.equal(f.evidence.sensitive, true);
  assert.equal(f.evidence.table_level_select, false);
  assert.equal(f.evidence.column_level_select, true);
  assert.deepEqual(f.evidence.roles_exposed, ["anon"]);
});

test("classifyColumnGrant: GOLDEN fixture (spec step 4) — anon col grant on sensitive column of locked table -> flagged", () => {
  // Table-level SELECT is denied (table looks locked) but a column-level
  // SELECT grant on 'cpf' lets anon read it. This is the bypass.
  const row = {
    schema_name: "public",
    table_name: "patients",
    column_name: "cpf",
    data_type: "text",
    anon_col_select: true,
    auth_col_select: false,
    anon_table_select: false,
    auth_table_select: false,
  };
  const f = classifyColumnGrant(row);
  assert.ok(f, "expected a finding for sensitive column bypass");
  assert.equal(f.severity, "critical");
  assert.equal(f.evidence.sensitive, true);
  assert.equal(f.evidence.table_level_select, false);
  assert.ok(f.fix.sql.some((s) => s.includes("REVOKE SELECT(cpf)")));
});

test("classifyColumnGrant: non-sensitive column + table locked -> high (bypass)", () => {
  const f = classifyColumnGrant(GRANT_ROW({ column_name: "some_flag", data_type: "boolean" }));
  assert.ok(f);
  assert.equal(f.severity, "high");
  assert.equal(f.evidence.sensitive, false);
  assert.equal(f.evidence.table_level_select, false);
});

test("classifyColumnGrant: non-sensitive column + table also granted -> null (redundant, no additional exposure)", () => {
  const f = classifyColumnGrant(GRANT_ROW({ column_name: "title", anon_table_select: true }));
  assert.equal(f, null, "redundant column grant where table-level is already granted should be suppressed");
});

test("classifyColumnGrant: auth-only col_select on sensitive column -> critical", () => {
  const f = classifyColumnGrant(GRANT_ROW({ auth_col_select: true, anon_col_select: false }));
  assert.ok(f);
  assert.equal(f.severity, "critical");
  assert.deepEqual(f.evidence.roles_exposed, ["authenticated"]);
});

test("classifyColumnGrant: no col_select (only table-level) -> null", () => {
  const f = classifyColumnGrant(GRANT_ROW({ anon_col_select: false, anon_table_select: true }));
  assert.equal(f, null);
});

test("classifyColumnGrant: neither anon nor auth col_select -> null", () => {
  const f = classifyColumnGrant(GRANT_ROW({ anon_col_select: false, auth_col_select: false }));
  assert.equal(f, null);
});

test("classifyColumnGrant: no-column-name -> null", () => {
  const f = classifyColumnGrant(GRANT_ROW({ column_name: null }));
  assert.equal(f, null);
});

// ---------------------------------------------------------------------------
// findExposedSchemas
// ---------------------------------------------------------------------------

test("findExposedSchemas: custom schema is flagged", () => {
  const findings = findExposedSchemas(["public", "graphql_public", "billing_data"]);
  assert.equal(findings.length, 1);
  assert.equal(findings[0].check, "custom_schema_exposed");
  assert.equal(findings[0].severity, "low");
  assert.equal(findings[0].target, "schema:billing_data");
});

test("findExposedSchemas: known-safe schemas are skipped", () => {
  const findings = findExposedSchemas(["public", "graphql_public", "pg_catalog", "information_schema"]);
  assert.equal(findings.length, 0);
});

test("findExposedSchemas: internal postgres schemas are skipped", () => {
  const findings = findExposedSchemas(["public", "_pg_stat", "pg_toast_temp_3", "custom_api"]);
  assert.equal(findings.length, 1);
  assert.equal(findings[0].target, "schema:custom_api");
});

test("findExposedSchemas: empty/null/invalid input -> []", () => {
  assert.deepEqual(findExposedSchemas([]), []);
  assert.deepEqual(findExposedSchemas(null), []);
  assert.deepEqual(findExposedSchemas(undefined), []);
  assert.deepEqual(findExposedSchemas(["", "  ", null]), []);
});

test("findExposedSchemas: $user and $-prefixed tokens filtered (not schemas)", () => {
  // WO-7: pg_settings.search_path contains $user (a Postgres placeholder, not a schema).
  // The fixed code reads db_schema from Management API and filters $-prefixed tokens.
  const findings = findExposedSchemas(["$user", "public", "$myvar_schema"]);
  assert.equal(findings.length, 0, "$user and $-prefixed tokens are filtered, public is known-safe");
});

// ---------------------------------------------------------------------------
// processColumnGrants
// ---------------------------------------------------------------------------

test("processColumnGrants: mixed rows -> only grant rows produce findings", () => {
  const rows = [
    GRANT_ROW({ column_name: "email", anon_col_select: true, anon_table_select: false }),
    GRANT_ROW({ column_name: "id", anon_col_select: false, auth_col_select: false, anon_table_select: true }),
    GRANT_ROW({ column_name: "cpf", auth_col_select: true, anon_col_select: false, anon_table_select: false }),
  ];
  const findings = processColumnGrants(rows);
  const targets = findings.map((f) => f.target).sort();
  assert.deepEqual(targets, ["column:schema:public:table:users:col:cpf", "column:schema:public:table:users:col:email"]);
});

test("processColumnGrants: empty rows -> []", () => {
  assert.deepEqual(processColumnGrants([]), []);
});

// ---------------------------------------------------------------------------
// Round-trip: pure findings -> normalize -> assemble -> schema valid + no secrets
// ---------------------------------------------------------------------------

test("grants findings round-trip: normalize -> assembleResult -> schema valid + no secrets + deterministic", () => {
  const rows = [
    GRANT_ROW({ column_name: "email", anon_col_select: true, anon_table_select: false }),
    GRANT_ROW({ column_name: "phone", anon_col_select: true, auth_col_select: true, anon_table_select: false }),
  ];
  const raw = processColumnGrants(rows);
  const exposed = findExposedSchemas(["public", "billing_data"]);
  const allRaw = [...raw, ...exposed].map(normalizeFinding);

  const fixedAt = "2026-08-27T12:00:00.000Z";
  const opts = { project_ref: "ref-grants-01", mode: "audit-active", rawFindings: allRaw, generated_at: fixedAt };

  const result = assembleResult(opts);

  // 1. schema valid
  const { valid, errors } = validate(result, schema);
  assert.equal(valid, true, `schema violations: ${JSON.stringify(errors)}`);

  // 2. no secrets in output
  const secrets = scanForSecrets(JSON.stringify(result));
  assert.equal(secrets.length, 0, `secrets found: ${JSON.stringify(secrets)}`);

  // 3. deterministic ordering — same inputs => identical JSON
  const json1 = JSON.stringify(assembleResult(opts), null, 2);
  const json2 = JSON.stringify(assembleResult(opts), null, 2);
  assert.equal(json1, json2, "output must be deterministic");

  // 4. every finding has a populated, valid fix object
  for (const f of result.findings) {
    assert.ok(Array.isArray(f.fix.sql), `fix.sql missing on ${f.check}`);
    assert.ok(Array.isArray(f.fix.rollback_sql), `fix.rollback_sql missing on ${f.check}`);
  }
});
