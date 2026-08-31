// Tests for scripts/checks/history.js (WO-9: historical exposure detection)
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  redactQuery,
  isEnumeration,
  classifyHistoricalAccess,
  processHistoricalAccess,
  extractTableName,
  extractTableNames,
  isProbeQuery,
  isInternalQuery,
} from "../scripts/checks/history.js";

// --- redactQuery ---

test("redactQuery: CPF (11 digits) is redacted", () => {
  const q = "SELECT * FROM patient_photos WHERE cpf = '12345678901'";
  const r = redactQuery(q);
  assert.ok(r.includes("[REDACTED]"), "CPF redacted");
  assert.ok(!r.includes("12345678901"), "CPF value gone");
});

test("redactQuery: email is redacted", () => {
  const q = "SELECT email FROM users WHERE email = 'test@example.com'";
  const r = redactQuery(q);
  assert.ok(r.includes("[REDACTED]"), "email redacted");
  assert.ok(!r.includes("test@example.com"), "email value gone");
});

test("redactQuery: null/empty -> null", () => {
  assert.equal(redactQuery(null), null);
  assert.equal(redactQuery(""), null);
});

// --- isEnumeration ---

test("isEnumeration: LIMIT/OFFSET without WHERE -> true", () => {
  assert.equal(isEnumeration("SELECT * FROM users LIMIT 100 OFFSET 500"), true);
});

test("isEnumeration: SELECT with WHERE -> false", () => {
  assert.equal(isEnumeration("SELECT * FROM users WHERE id = $1"), false);
});

test("isEnumeration: no LIMIT/OFFSET -> false", () => {
  assert.equal(isEnumeration("SELECT * FROM users WHERE cpf = $1"), false);
});

test("isEnumeration: tautological WHERE true + LIMIT -> true", () => {
  assert.equal(isEnumeration('SELECT * FROM users WHERE true LIMIT 100'), true);
});

test("isEnumeration: tautological WHERE (true) + LIMIT -> true", () => {
  assert.equal(isEnumeration('SELECT * FROM users WHERE (true) LIMIT 100'), true);
});

test("isEnumeration: tautological WHERE 1=1 + LIMIT -> true", () => {
  assert.equal(isEnumeration("SELECT * FROM users WHERE 1=1 LIMIT 100"), true);
});

test("isEnumeration: real WHERE + LIMIT -> false", () => {
  assert.equal(isEnumeration("SELECT * FROM users WHERE id = $1 LIMIT 100"), false);
});

test("isEnumeration: INSERT with LIMIT -> false", () => {
  assert.equal(isEnumeration("INSERT INTO users (id) VALUES (1) LIMIT 100"), false);
});

test("isEnumeration: OFFSET only (no LIMIT) without WHERE -> true", () => {
  assert.equal(isEnumeration("SELECT * FROM users OFFSET 500"), true);
});

// --- extractTableName / extractTableNames ---

test("extractTableName: \"schema\".\"table\" format -> table name", () => {
  assert.equal(extractTableName('SELECT * FROM "public"."patient_photos" WHERE id = $1'), "patient_photos");
});

test("extractTableName: schema.table (unquoted) -> table name", () => {
  assert.equal(extractTableName("SELECT * FROM public.patient_photos WHERE id = $1"), "patient_photos");
});

test("extractTableName: plain table name -> table name", () => {
  assert.equal(extractTableName("SELECT * FROM patient_photos WHERE id = $1"), "patient_photos");
});

test("extractTableName: INSERT INTO \"schema\".\"table\" -> table name", () => {
  assert.equal(extractTableName('INSERT INTO "public"."patient_photos" (a) VALUES (1)'), "patient_photos");
});

test("extractTableName: UPDATE \"schema\".\"table\" -> table name", () => {
  assert.equal(extractTableName('UPDATE "public"."patient_photos" SET url = $1 WHERE id = $2'), "patient_photos");
});

test("extractTableName: DELETE FROM \"schema\".\"table\" -> table name", () => {
  assert.equal(extractTableName('DELETE FROM "public"."patient_photos" WHERE id = $1'), "patient_photos");
});

test("extractTableName: schema-qualified preference over alias", () => {
  // CTE wraps the real table; extractTableName should still find the real table
  const q = 'WITH _r AS (SELECT * FROM "public"."patient_photos") SELECT * FROM _r LIMIT 100';
  assert.equal(extractTableName(q, ["patient_photos"]), "patient_photos");
});

test("extractTableNames: skips system catalogs", () => {
  assert.equal(extractTableNames('SELECT * FROM pg_catalog.pg_proc').length, 0);
  assert.equal(extractTableNames('SELECT * FROM information_schema.columns').length, 0);
});

test("extractTableNames: skips function-call references", () => {
  assert.equal(extractTableNames("SELECT * FROM json_to_record('{}')").length, 0);
  assert.equal(extractTableNames("SELECT * FROM unnest(ARRAY[1,2,3])").length, 0);
});

test("extractTableNames: returns empty for non-table queries", () => {
  assert.equal(extractTableNames("SELECT set_config('role', 'anon', false)").length, 0);
});

// --- isProbeQuery ---

test("isProbeQuery: tagged probe -> true", () => {
  assert.equal(isProbeQuery("/* supa360-probe */ SELECT r.rolname, s.query FROM extensions.pg_stat_statements s"), true);
});

test("isProbeQuery: legacy unmarked probe (SELECT * LIMIT 1, no WHERE) -> true", () => {
  assert.equal(isProbeQuery('SELECT * FROM "public"."patient_photos" LIMIT 1'), true);
  assert.equal(isProbeQuery("SELECT * FROM patients LIMIT 1"), true);
});

test("isProbeQuery: per-key lookup with WHERE -> false", () => {
  assert.equal(isProbeQuery('SELECT * FROM "public"."patient_photos" WHERE id = $1 LIMIT 1'), false);
});

test("isProbeQuery: SELECT without LIMIT 1 -> false", () => {
  assert.equal(isProbeQuery('SELECT * FROM "public"."patient_photos" LIMIT 100'), false);
});

test("isProbeQuery: non-SELECT tagged query -> true", () => {
  assert.equal(isProbeQuery("/* supa360-probe */ INSERT INTO foo VALUES (1)"), true);
});

// --- isInternalQuery ---

test("isInternalQuery: set_config -> true", () => {
  assert.equal(isInternalQuery("SELECT set_config('role', 'anon', false)"), true);
  assert.equal(isInternalQuery("SELECT set_config('search_path', 'public', false)"), true);
});

test("isInternalQuery: obj_description -> true", () => {
  assert.equal(isInternalQuery("SELECT obj_description(12345, 'pg_class')"), true);
});

test("isInternalQuery: pg_catalog reference -> true", () => {
  assert.equal(isInternalQuery('SELECT proname FROM pg_catalog.pg_proc'), true);
});

test("isInternalQuery: real table query -> false", () => {
  assert.equal(isInternalQuery('SELECT * FROM "public"."patient_photos" WHERE id = $1'), false);
});

test("isInternalQuery: INSERT into real table -> false", () => {
  assert.equal(isInternalQuery('INSERT INTO "public"."patient_photos" (a) VALUES (1)'), false);
});

// --- classifyHistoricalAccess ---

test("classifyHistoricalAccess: rows=0 -> null (no confirmed data access)", () => {
  assert.equal(classifyHistoricalAccess({ query: "SELECT * FROM x WHERE 1=0", calls: 1, rows: 0 }), null);
});

test("classifyHistoricalAccess: SELECT rows>0 on table-with-data -> critical", () => {
  const f = classifyHistoricalAccess(
    { rolname: "anon", query: "SELECT * FROM patient_photos WHERE id = $1", calls: 9405, rows: 9405, stats_since: "2025-08-22" },
    ["patient_photos"]
  );
  assert.ok(f);
  assert.equal(f.severity, "critical");
  assert.equal(f.confidence, "confirmed");
  assert.equal(f.evidence.rows, 9405);
  assert.ok(!f.evidence.query.includes("9405"), "row count not in query text");
});

test("classifyHistoricalAccess: SELECT on \"schema\".\"table\" with data -> critical (BUG 2 fix)", () => {
  // PostgREST emits FROM "public"."patient_photos" — must extract "patient_photos", not "public"
  const f = classifyHistoricalAccess(
    { rolname: "anon", query: 'SELECT * FROM "public"."patient_photos" WHERE id = $1', calls: 9405, rows: 9405, stats_since: "2025-08-22" },
    ["patient_photos"]
  );
  assert.ok(f, "should produce a finding (not null)");
  assert.equal(f.severity, "critical", "should escalate to critical because table holds data");
  assert.equal(f.evidence.table_name, "patient_photos", "must extract table name, not schema name");
  assert.equal(f.evidence.table_has_data, true, "must detect table currently holds data");
  assert.equal(f.check, "anon_historical_read_critical");
});

test("classifyHistoricalAccess: INSERT -> high", () => {
  const f = classifyHistoricalAccess(
    { rolname: "anon", query: "INSERT INTO patient_photos (...) VALUES (...)", calls: 309, rows: 309 },
    ["patient_photos"]
  );
  assert.ok(f);
  assert.equal(f.severity, "high");
  assert.equal(f.check, "anon_historical_write");
});

test("classifyHistoricalAccess: INSERT INTO \"schema\".\"table\" -> high (BUG 2 fix)", () => {
  const f = classifyHistoricalAccess(
    { rolname: "anon", query: 'INSERT INTO "public"."patient_photos" (a) VALUES (1)', calls: 309, rows: 309 },
    ["patient_photos"]
  );
  assert.ok(f);
  assert.equal(f.evidence.table_name, "patient_photos");
  assert.equal(f.check, "anon_historical_write");
});

test("classifyHistoricalAccess: UPDATE \"schema\".\"table\" -> high", () => {
  const f = classifyHistoricalAccess(
    { rolname: "anon", query: 'UPDATE "public"."patient_photos" SET url = $1 WHERE id = $2', calls: 42, rows: 42 },
    ["patient_photos"]
  );
  assert.ok(f);
  assert.equal(f.evidence.table_name, "patient_photos");
  assert.equal(f.check, "anon_historical_write");
  assert.equal(f.severity, "high");
});

test("classifyHistoricalAccess: DELETE FROM \"schema\".\"table\" -> high", () => {
  const f = classifyHistoricalAccess(
    { rolname: "anon", query: 'DELETE FROM "public"."patient_photos" WHERE id = $1', calls: 10, rows: 10 },
    ["patient_photos"]
  );
  assert.ok(f);
  assert.equal(f.evidence.table_name, "patient_photos");
  assert.equal(f.check, "anon_historical_write");
});

test("classifyHistoricalAccess: LIMIT/OFFSET enumeration -> enumeration flag true (BUG 5 fix)", () => {
  const f = classifyHistoricalAccess(
    { rolname: "anon", query: "SELECT patient_cpf FROM patient_photos LIMIT 100 OFFSET 500", calls: 3, rows: 3 },
    ["patient_photos"]
  );
  assert.ok(f);
  assert.equal(f.check, "anon_historical_enumeration");
  assert.equal(f.evidence.enumeration, true);
});

test("classifyHistoricalAccess: per-key lookup with WHERE -> NOT enumeration (BUG 5 fix)", () => {
  // A per-key lookup (WHERE col = $1) should NOT be flagged as enumeration
  const f = classifyHistoricalAccess(
    { rolname: "anon", query: "SELECT * FROM patient_photos WHERE patient_cpf = $1 LIMIT 1000", calls: 9405, rows: 9405 },
    ["patient_photos"]
  );
  assert.ok(f);
  assert.equal(f.evidence.enumeration, false, "per-key lookup with WHERE should not be enumeration");
  assert.equal(f.check, "anon_historical_read_critical"); // not enumeration, table has data
});

test("classifyHistoricalAccess: WHERE-less scan with WHERE true -> enumeration (BUG 5 fix)", () => {
  // PostgREST may emit WHERE true as a tautology — still enumeration
  const f = classifyHistoricalAccess(
    { rolname: "anon", query: "SELECT patient_cpf FROM patient_photos WHERE true LIMIT 1000", calls: 3, rows: 100 },
    ["patient_photos"]
  );
  assert.ok(f);
  assert.equal(f.evidence.enumeration, true, "tautological WHERE true should still be enumeration");
  assert.equal(f.check, "anon_historical_enumeration");
});

test("classifyHistoricalAccess: tagged probe query -> null (BUG 3 fix)", () => {
  const f = classifyHistoricalAccess(
    { rolname: "anon", query: "/* supa360-probe */ SELECT * FROM patient_photos LIMIT 1", calls: 1, rows: 1 },
    ["patient_photos"]
  );
  assert.equal(f, null, "tagged probe should be filtered out");
});

test("classifyHistoricalAccess: legacy unmarked probe (SELECT * LIMIT 1) -> null (BUG 3 fix)", () => {
  const f = classifyHistoricalAccess(
    { rolname: "anon", query: 'SELECT * FROM "public"."patient_photos" LIMIT 1', calls: 1, rows: 1 },
    ["patient_photos"]
  );
  assert.equal(f, null, "legacy unmarked probe should be filtered out");
});

test("classifyHistoricalAccess: set_config internal -> null (BUG 4 fix)", () => {
  const f = classifyHistoricalAccess(
    { rolname: "anon", query: "SELECT set_config('role', 'anon', false)", calls: 1, rows: 1 },
    ["patient_photos"]
  );
  assert.equal(f, null, "set_config internal should be filtered out");
});

test("classifyHistoricalAccess: obj_description internal -> null (BUG 4 fix)", () => {
  const f = classifyHistoricalAccess(
    { rolname: "anon", query: "SELECT obj_description(12345, 'pg_class')", calls: 1, rows: 1 },
    ["patient_photos"]
  );
  assert.equal(f, null, "obj_description internal should be filtered out");
});

test("classifyHistoricalAccess: pg_catalog query -> null (BUG 4 fix)", () => {
  const f = classifyHistoricalAccess(
    { rolname: "anon", query: 'SELECT proname FROM pg_catalog.pg_proc WHERE proname = $1', calls: 1, rows: 1 },
    ["patient_photos"]
  );
  assert.equal(f, null, "pg_catalog reference should be filtered out");
});

test("classifyHistoricalAccess: table not in scanned list -> high (table_has_data=false)", () => {
  // Table exists in the query but is NOT in the current scan → table_has_data=false
  const f = classifyHistoricalAccess(
    { rolname: "anon", query: 'SELECT * FROM "public"."old_table" WHERE id = $1', calls: 100, rows: 100 },
    ["patient_photos"]
  );
  assert.ok(f);
  assert.equal(f.severity, "high");
  assert.equal(f.evidence.table_has_data, false);
  assert.equal(f.check, "anon_historical_read");
});

test("classifyHistoricalAccess: has title and explain (context text)", () => {
  const f = classifyHistoricalAccess(
    { rolname: "anon", query: "SELECT * FROM patient_photos WHERE id = $1", calls: 9405, rows: 9405, stats_since: "2025-08-22" },
    ["patient_photos"]
  );
  assert.ok(f);
  assert.ok(f.title, "should have a title");
  assert.ok(f.explain, "should have an explanation with meaning/context");
  assert.ok(f.explain.includes("breach-notification") || f.explain.includes("preserve"), "should mention breach-notification or evidence preservation");
});

test("classifyHistoricalAccess: CPF redacted in evidence.query", () => {
  const f = classifyHistoricalAccess(
    { rolname: "anon", query: "SELECT * FROM users WHERE cpf = '12345678901'", calls: 1, rows: 1 },
    ["users"]
  );
  assert.ok(f);
  assert.ok(!f.evidence.query.includes("12345678901"), "CPF value redacted in query");
  assert.ok(f.evidence.query.includes("[REDACTED]"), "redaction marker present");
});

// --- processHistoricalAccess ---

test("processHistoricalAccess: empty rows -> history_available=false", () => {
  const result = processHistoricalAccess([]);
  assert.equal(result.history_available, false);
  assert.equal(result.findings.length, 0);
  assert.ok(result.note, "note explains why");
});

test("processHistoricalAccess: null -> history_available=false, note set", () => {
  const result = processHistoricalAccess(null);
  assert.equal(result.history_available, false);
  assert.ok(result.note, "never interpret absence as clean");
});

test("processHistoricalAccess: rows with data -> findings + history_available=true", () => {
  const rows = [
    { rolname: "anon", query: "SELECT * FROM t WHERE c = $1", calls: 5, rows: 5, stats_since: "2025-08-22" },
    { rolname: "anon", query: "SELECT * FROM t WHERE c = $1", calls: 1, rows: 0, stats_since: "2025-08-22" }, // rows=0 -> skipped
  ];
  const result = processHistoricalAccess(rows, ["t"]);
  assert.equal(result.history_available, true);
  assert.equal(result.findings.length, 1, "only row>0 finding");
  assert.equal(result.stats_since, "2025-08-22");
});

test("processHistoricalAccess: aggregation merges same role/table/verb", () => {
  // Two different SELECT queries on the same table by anon should aggregate
  // into ONE finding with summed calls/rows.
  const rows = [
    { rolname: "anon", query: "SELECT * FROM patient_photos WHERE id = $1", calls: 5, rows: 5, stats_since: "2025-08-22" },
    { rolname: "anon", query: "SELECT * FROM patient_photos WHERE url = $1", calls: 3, rows: 3, stats_since: "2025-08-22" },
    { rolname: "anon", query: "SELECT * FROM patient_photos WHERE cpf = $1", calls: 2, rows: 2, stats_since: "2025-08-22" },
  ];
  const result = processHistoricalAccess(rows, ["patient_photos"]);
  assert.equal(result.findings.length, 1, "should aggregate into one finding");
  const f = result.findings[0];
  assert.equal(f.evidence.calls, 10, "calls should be summed");
  assert.equal(f.evidence.rows, 10, "rows should be summed");
  assert.equal(f.evidence.table_name, "patient_photos");
  assert.equal(f.evidence.query_count, 3, "should track number of distinct queries");
});

test("processHistoricalAccess: separate findings for different tables", () => {
  const rows = [
    { rolname: "anon", query: "SELECT * FROM patient_photos WHERE id = $1", calls: 5, rows: 5, stats_since: "2025-08-22" },
    { rolname: "anon", query: "SELECT * FROM patients WHERE id = $1", calls: 3, rows: 3, stats_since: "2025-08-22" },
  ];
  const result = processHistoricalAccess(rows, ["patient_photos", "patients"]);
  assert.equal(result.findings.length, 2, "should have one finding per table");
  const tables = result.findings.map((f) => f.evidence.table_name).sort();
  assert.deepEqual(tables, ["patient_photos", "patients"]);
});

test("processHistoricalAccess: probes filtered before aggregation", () => {
  const rows = [
    { rolname: "anon", query: "/* supa360-probe */ SELECT * FROM patient_photos LIMIT 1", calls: 1, rows: 1 },
    { rolname: "anon", query: 'SELECT * FROM "public"."patient_photos" LIMIT 1', calls: 1, rows: 1 }, // legacy probe
    { rolname: "anon", query: "SELECT * FROM patient_photos WHERE id = $1", calls: 5, rows: 5, stats_since: "2025-08-22" },
  ];
  const result = processHistoricalAccess(rows, ["patient_photos"]);
  assert.equal(result.findings.length, 1, "only the real query should survive");
  assert.equal(result.findings[0].evidence.calls, 5);
  assert.equal(result.findings[0].evidence.rows, 5);
});

test("processHistoricalAccess: all probes/internals -> empty findings with note", () => {
  const rows = [
    { rolname: "anon", query: "/* supa360-probe */ SELECT * FROM patient_photos LIMIT 1", calls: 1, rows: 1 },
    { rolname: "anon", query: "SELECT set_config('role', 'anon', false)", calls: 1, rows: 1 },
  ];
  const result = processHistoricalAccess(rows, ["patient_photos"]);
  assert.equal(result.findings.length, 0, "all filtered out");
  assert.equal(result.history_available, true, "history exists but all were probes/internals");
  assert.ok(result.note, "note explains why no findings");
});

test("processHistoricalAccess: enumeration group aggregated separately from read group", () => {
  const rows = [
    // Enumeration scan on patient_photos
    { rolname: "anon", query: "SELECT patient_cpf FROM patient_photos LIMIT 1000", calls: 3, rows: 3000, stats_since: "2025-08-22" },
    // Per-key lookup on patient_photos
    { rolname: "anon", query: "SELECT * FROM patient_photos WHERE id = $1 LIMIT 1000", calls: 9405, rows: 9405, stats_since: "2025-08-22" },
  ];
  const result = processHistoricalAccess(rows, ["patient_photos"]);
  // Both are SELECT on patient_photos by anon → same group
  assert.equal(result.findings.length, 1, "same role/table/verb → one group");
  const f = result.findings[0];
  assert.equal(f.evidence.enumeration, true, "group should have enumeration=true (any in group)");
  assert.equal(f.evidence.calls, 9408, "calls summed");
  assert.equal(f.evidence.rows, 12405, "rows summed");
  assert.equal(f.evidence.enumeration_calls, 3, "3 enumeration call(s) in group");
  assert.equal(f.evidence.lookup_calls, 9405, "9405 per-key lookup call(s) in group");
  assert.equal(f.evidence.enumeration_calls + f.evidence.lookup_calls, f.evidence.calls, "invariant: enum_calls + lookup_calls === calls");
});

test("processHistoricalAccess: separate groups for anon vs authenticated", () => {
  const rows = [
    { rolname: "anon", query: "SELECT * FROM patients WHERE id = $1", calls: 5, rows: 5, stats_since: "2025-08-22" },
    { rolname: "authenticated", query: "SELECT * FROM patients WHERE id = $1", calls: 3, rows: 3, stats_since: "2025-08-22" },
  ];
  const result = processHistoricalAccess(rows, ["patients"]);
  assert.equal(result.findings.length, 2, "separate roles → separate findings");
  const roles = result.findings.map((f) => f.evidence.role).sort();
  assert.deepEqual(roles, ["anon", "authenticated"]);
});

test("processHistoricalAccess: schema-aware grouping (same table name, different schemas)", () => {
  // Two tables named "logs" in different schemas should be separate findings
  const rows = [
    { rolname: "anon", query: 'SELECT * FROM "public"."logs" WHERE id = $1', calls: 5, rows: 5, stats_since: "2025-08-22" },
    { rolname: "anon", query: 'SELECT * FROM "custom"."logs" WHERE id = $1', calls: 3, rows: 3, stats_since: "2025-08-22" },
  ];
  const result = processHistoricalAccess(rows, ["logs"]);
  assert.equal(result.findings.length, 2, "different schemas → separate findings");
  const schemas = result.findings.map((f) => f.evidence.schema).sort();
  assert.deepEqual(schemas, ["custom", "public"]);
});

test("processHistoricalAccess: schema field present in evidence for qualified queries", () => {
  const rows = [
    { rolname: "anon", query: 'SELECT * FROM "public"."patient_photos" WHERE id = $1', calls: 9405, rows: 9405, stats_since: "2025-08-22" },
  ];
  const result = processHistoricalAccess(rows, ["patient_photos"]);
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].evidence.schema, "public", "schema extracted from query");
  assert.equal(result.findings[0].evidence.table_name, "patient_photos", "table name is just the table");
  assert.equal(result.findings[0].evidence.qualified_table, "public.patient_photos", "qualified table in evidence");
  assert.equal(result.findings[0].target, "table:public.patient_photos:role:anon:verb:SELECT", "target includes verb (WO-17: no dupe between verbs)");
});

// --- CTE-wrapped PostgREST query shapes (the no-op bug from Solvr #163) ---
// PostgREST wraps many queries in CTEs. The old sqlVerb used lastIndexOf(')')
// which found the wrong closing paren when the OUTER query had its own WHERE
// clause, returning "OTHER" and causing zero findings.

test("classifyHistoricalAccess: CTE-wrapped SELECT with outer WHERE -> classified (not null)", () => {
  // PostgREST CTE + outer WHERE — the lastIndexOf(')') bug would find the
  // wrong ')' and return "OTHER", causing the row to be skipped entirely.
  const f = classifyHistoricalAccess(
    { rolname: "anon", query: 'WITH _rq AS (SELECT * FROM "public"."patient_photos") SELECT * FROM _rq WHERE ("id"::bigint = $1) LIMIT 1000', calls: 9405, rows: 9405, stats_since: "2025-08-22" },
    ["patient_photos"]
  );
  assert.ok(f, "CTE-wrapped query must produce a finding (not null — was the no-op bug)");
  assert.equal(f.severity, "critical", "table holds data → critical");
  assert.equal(f.check, "anon_historical_read_critical");
  assert.equal(f.evidence.table_name, "patient_photos");
});

test("classifyHistoricalAccess: CTE-wrapped enumeration (no outer WHERE) -> enumeration", () => {
  const f = classifyHistoricalAccess(
    { rolname: "anon", query: 'WITH _rq AS (SELECT "patient_cpf" FROM "public"."patient_photos") SELECT * FROM _rq LIMIT 100000', calls: 3, rows: 100000, stats_since: "2025-08-22" },
    ["patient_photos"]
  );
  assert.ok(f, "CTE-wrapped enumeration must produce a finding");
  assert.equal(f.check, "anon_historical_enumeration");
  assert.equal(f.evidence.enumeration, true);
});

test("classifyHistoricalAccess: non-CTE SELECT (PostgREST simple) -> classified", () => {
  const f = classifyHistoricalAccess(
    { rolname: "anon", query: 'SELECT "id","patient_cpf","url" FROM "public"."patient_photos" WHERE ("patient_cpf"::text = $1) LIMIT 1000', calls: 9405, rows: 9405, stats_since: "2025-08-22" },
    ["patient_photos"]
  );
  assert.ok(f, "non-CTE PostgREST query must produce a finding");
  assert.equal(f.severity, "critical");
  assert.equal(f.evidence.table_name, "patient_photos");
  assert.equal(f.evidence.enumeration, false, "per-key lookup with WHERE is NOT enumeration");
});

test("classifyHistoricalAccess: 9,405-call breach simulation (PostgREST real format)", () => {
  // The exact scenario from the architect's live run: 9,405 calls returning
  // 9,405 rows from patient_photos via anon. Must be CRITICAL, not zero findings.
  const rows = [
    { rolname: "anon", query: 'SELECT "id","patient_cpf","url" FROM "public"."patient_photos" WHERE ("id"::bigint = $1) LIMIT 1000', calls: 9405, rows: 9405, stats_since: "2025-08-22" },
  ];
  const result = processHistoricalAccess(rows, ["patient_photos"]);
  assert.equal(result.findings.length, 1, "must produce exactly 1 finding");
  const f = result.findings[0];
  assert.equal(f.severity, "critical", "9,405-row READ of a table holding data = CRITICAL");
  assert.equal(f.check, "anon_historical_read_critical");
  assert.equal(f.evidence.rows, 9405);
  assert.equal(f.evidence.table_has_data, true, "table_has_data must be true (BUG 1)");
  assert.equal(f.evidence.table_name, "patient_photos", "must extract table name, not schema (BUG 2)");
  assert.equal(f.evidence.schema, "public");
  assert.equal(f.evidence.qualified_table, "public.patient_photos");
  assert.ok(f.title, "has title with meaning");
  assert.ok(f.explain.includes("breach-notification") || f.explain.includes("preserve"), "explain has context/meaning");
});

test("classifyHistoricalAccess: WHERE-less LIMIT enumeration (no CTE) -> enumeration", () => {
  const f = classifyHistoricalAccess(
    { rolname: "anon", query: 'SELECT "patient_cpf" FROM "public"."patient_photos" LIMIT 100000', calls: 3, rows: 100000 },
    ["patient_photos"]
  );
  assert.ok(f);
  assert.equal(f.check, "anon_historical_enumeration");
  assert.equal(f.evidence.enumeration, true);
  assert.equal(f.severity, "critical", "table holds data → critical");
});

// --- PostgREST CTE-wrapped write operations (Solvr #163: real PostgREST format) ---
// PostgREST wraps ALL verbs in a CTE: the real operation (DELETE/INSERT/UPDATE)
// is inside pgrst_source, while the outer wrapper is always SELECT.
// The old sqlVerb returned "OTHER" (or mis-detected as SELECT) for these,
// causing zero findings on real operations.

test("classifyHistoricalAccess: DELETE inside CTE -> classified as DELETE (not SELECT)", () => {
  // PostgREST wraps DELETE in a CTE: WITH pgrst_source AS (DELETE FROM ...) SELECT * FROM pgrst_source
  const f = classifyHistoricalAccess(
    { rolname: "anon", query: 'WITH pgrst_source AS (DELETE FROM "public"."patient_photos" WHERE ("id"::bigint = $1)) SELECT * FROM pgrst_source', calls: 500, rows: 500, stats_since: "2025-08-22" },
    ["patient_photos"]
  );
  assert.ok(f, "DELETE-in-CTE must produce a finding (not null)");
  assert.equal(f.evidence.verb, "DELETE", "must detect DELETE inside CTE, not SELECT");
  assert.equal(f.check, "anon_historical_write");
  assert.equal(f.severity, "high");
  assert.equal(f.evidence.table_name, "patient_photos");
});

test("classifyHistoricalAccess: INSERT inside CTE -> classified as INSERT", () => {
  const f = classifyHistoricalAccess(
    { rolname: "anon", query: 'WITH pgrst_source AS (INSERT INTO "public"."patient_photos" ("patient_cpf","url") VALUES ($1, $2)) SELECT * FROM pgrst_source', calls: 309, rows: 309 },
    ["patient_photos"]
  );
  assert.ok(f, "INSERT-in-CTE must produce a finding");
  assert.equal(f.evidence.verb, "INSERT", "must detect INSERT inside CTE");
  assert.equal(f.check, "anon_historical_write");
});

test("classifyHistoricalAccess: UPDATE inside CTE -> classified as UPDATE", () => {
  const f = classifyHistoricalAccess(
    { rolname: "anon", query: 'WITH pgrst_source AS (UPDATE "public"."patient_photos" SET "url" = $1 WHERE ("id"::bigint = $2)) SELECT * FROM pgrst_source', calls: 42, rows: 42 },
    ["patient_photos"]
  );
  assert.ok(f, "UPDATE-in-CTE must produce a finding");
  assert.equal(f.evidence.verb, "UPDATE", "must detect UPDATE inside CTE");
  assert.equal(f.check, "anon_historical_write");
});

test("classifyHistoricalAccess: 9,405-call breach via pgrst_source CTE -> CRITICAL finding", () => {
  // The exact scenario the architect found: a 9,405-call anon READ of
  // patient_photos that PostgREST wraps in a CTE. Must be CRITICAL.
  const rows = [
    { rolname: "anon", query: 'WITH pgrst_source AS (SELECT "id","patient_cpf","url" FROM "public"."patient_photos" WHERE ("id"::bigint = $1)) SELECT * FROM pgrst_source', calls: 9405, rows: 9405, stats_since: "2025-08-22" },
  ];
  const result = processHistoricalAccess(rows, ["patient_photos"]);
  assert.equal(result.findings.length, 1, "must produce exactly 1 finding (not zero)");
  const f = result.findings[0];
  assert.equal(f.severity, "critical");
  assert.equal(f.check, "anon_historical_read_critical");
  assert.equal(f.evidence.verb, "SELECT");
  assert.equal(f.evidence.table_name, "patient_photos");
  assert.equal(f.evidence.rows, 9405);
  assert.equal(f.evidence.calls, 9405);
  assert.equal(f.evidence.table_has_data, true);
});

test("classifyHistoricalAccess: nested CTE with outer subquery (PostgREST 549-char format)", () => {
  // Real PostgREST format: WITH _POSTGREST_T AS (SELECT * FROM (SELECT ... FROM real_table) _POSTGREST_T) SELECT ...
  // _POSTGREST_T is a CTE alias (filtered), but the real table inside the CTE body is found.
  const f = classifyHistoricalAccess(
    { rolename: "anon", query: 'WITH _POSTGREST_T AS (SELECT * FROM (SELECT "id","patient_cpf","url" FROM "public"."patient_photos") _POSTGREST_T) SELECT * FROM _POSTGREST_T WHERE ("id"::bigint = $1)', calls: 1, rows: 1 },
    ["patient_photos"]
  );
  assert.ok(f, "nested CTE must produce a finding (not null — was the no-op bug)");
  assert.equal(f.evidence.verb, "SELECT", "must detect SELECT even in nested CTE");
  assert.equal(f.evidence.table_name, "patient_photos", "must extract real table from CTE body");
});

test("design call: enumeration_calls + lookup_calls preserved in aggregated finding", () => {
  // 55 WHERE-less enumeration scans + 9,405 per-key lookups on the same table.
  // Must be ONE finding with both counts preserved (not flattened to enum=true).
  const rows = [
    { rolname: "anon", query: 'WITH pgrst_source AS (SELECT "patient_cpf" FROM "public"."patient_photos") SELECT * FROM pgrst_source LIMIT 100000', calls: 55, rows: 5500000, stats_since: "2025-08-22" },
    { rolname: "anon", query: 'SELECT "id","patient_cpf","url" FROM "public"."patient_photos" WHERE ("id"::bigint = $1) LIMIT 1000', calls: 9405, rows: 9405, stats_since: "2025-08-22" },
  ];
  const result = processHistoricalAccess(rows, ["patient_photos"]);
  assert.equal(result.findings.length, 1, "same role/table/verb → one group");
  const f = result.findings[0];
  assert.equal(f.evidence.enumeration, true, "any enumeration in group → enumeration=true");
  assert.equal(f.evidence.enumeration_calls, 55, "55 enumeration call(s)");
  assert.equal(f.evidence.lookup_calls, 9405, "9405 lookup call(s)");
  assert.equal(f.evidence.enumeration_calls + f.evidence.lookup_calls, f.evidence.calls, "invariant: enum_calls + lookup_calls === calls");
  assert.equal(f.evidence.calls, 9460, "calls summed: 55 + 9405");
  assert.equal(f.evidence.rows, 5509405, "rows summed: 5500000 + 9405");
  assert.equal(f.severity, "critical", "table holds data → critical");
});

test("isProbeQuery: count(*) accessibility probe (select $1 as test) -> true", () => {
  assert.equal(isProbeQuery('SELECT $1 AS test, count(*)::text AS result FROM "public"."patient_photos"'), true);
});

test("isProbeQuery: count(*) as anon_visible_* probe -> true", () => {
  assert.equal(isProbeQuery('SELECT count(*) AS anon_visible_rows FROM "public"."patient_photos"'), true);
  assert.equal(isProbeQuery('SELECT count(*) AS authed_visible_rows FROM "public"."patient_photos"'), true);
});

test("isProbeQuery: count(*) probe is NOT confused with real SELECT", () => {
  // A bare count(*) of a sensitive table is attacker recon, not our probe.
  // Must NOT be suppressed.
  assert.equal(isProbeQuery('SELECT count(*) FROM "public"."patient_photos"'), false, "bare count(*) is recon, not our probe");
  assert.equal(isProbeQuery('SELECT count(*) FROM public.patient_photos WHERE id = $1'), false, "has WHERE → not a probe");
});

test("isProbeQuery: SELECT $1 AS test probe WITH WHERE is still a probe", () => {
  // PostgREST accessibility probe with WHERE (e.g. bucket_id=$2 for storage.objects)
  assert.equal(isProbeQuery('SELECT $1 AS test, count(*)::text AS result FROM "storage"."objects" WHERE bucket_id = $2'), true);
});

test("processHistoricalAccess: excluded_count tracks filtered probes/internals", () => {
  const rows = [
    { rolename: "anon", query: "/* supa360-probe */ SELECT r.rolname FROM extensions.pg_stat_statements", calls: 1, rows: 1 },
    { rolname: "anon", query: 'SELECT $1 AS test, count(*)::text AS result FROM "public"."patient_photos"', calls: 1, rows: 1 },
    { rolename: "anon", query: "SELECT set_config('role', 'anon', false)", calls: 1, rows: 1 },
    { rolname: "anon", query: "SELECT * FROM patient_photos WHERE id = $1", calls: 5, rows: 5, stats_since: "2025-08-22" },
  ];
  const result = processHistoricalAccess(rows, ["patient_photos"]);
  assert.equal(result.excluded_count, 3, "3 filtered (1 tagged probe + 1 count probe + 1 internal)");
  assert.equal(result.findings.length, 1);
});

test("processHistoricalAccess: schema resolution merges bare + qualified storage.objects", () => {
  const rows = [
    { rolname: "anon", query: 'WITH pgrst_source AS (INSERT INTO "storage"."objects" ("name","bucket_id") VALUES ($1, $2)) SELECT * FROM pgrst_source', calls: 7, rows: 7 },
    { rolname: "anon", query: 'WITH pgrst_source AS (INSERT INTO objects ("name","bucket_id") VALUES ($1, $2)) SELECT * FROM pgrst_source', calls: 304, rows: 304 },
  ];
  const tableSchemas = { objects: "storage" };
  const result = processHistoricalAccess(rows, ["objects"], tableSchemas);
  assert.equal(result.findings.length, 1, "bare + qualified should merge into one group");
  const f = result.findings[0];
  assert.equal(f.evidence.schema, "storage");
  assert.equal(f.evidence.qualified_table, "storage.objects");
  assert.equal(f.evidence.calls, 311, "7 + 304 merged");
});

// WO-17: different verbs on the same table must produce separate targets
// (same id collision was the root cause of 140 duplicate finding IDs).
test("WO-17: mixed verbs on same table produce separate targets (no id collision)", () => {
  const rows = [
    { rolname: "anon", query: 'SELECT * FROM "public"."sensitive_photos" LIMIT 1000', calls: 37, rows: 37, stats_since: "2025-08-22" },
    { rolname: "anon", query: 'WITH pgrst_source AS (INSERT INTO "public"."sensitive_photos" ("url") VALUES ($1)) SELECT * FROM pgrst_source', calls: 310, rows: 310, stats_since: "2025-08-22" },
    { rolname: "anon", query: 'WITH pgrst_source AS (DELETE FROM "public"."sensitive_photos" WHERE "id" = $1) SELECT * FROM pgrst_source', calls: 2, rows: 2, stats_since: "2025-08-22" },
  ];
  const result = processHistoricalAccess(rows, ["sensitive_photos"], { sensitive_photos: "public" });
  assert.equal(result.findings.length, 3, "three distinct verb groups -> three findings");
  const targets = result.findings.map((f) => f.target);
  assert.equal(new Set(targets).size, 3, "all three targets must be distinct (no id collision)");
  assert.ok(targets.some((t) => t.includes(":verb:SELECT")), "should have SELECT target");
  assert.ok(targets.some((t) => t.includes(":verb:INSERT")), "should have INSERT target");
  assert.ok(targets.some((t) => t.includes(":verb:DELETE")), "should have DELETE target");
});

// WO-18: enumeration volume must report WHERE-less-only counts, not group totals.
// The group has 37 bulk scans + 9405 per-key lookups = 9460 total calls.
// The finding must NOT claim "9460 WHERE-less call(s)" — only 37 are enumeration.
test("WO-18: enumeration reason reports enumeration-specific counts, not group totals", () => {
  const rows = [
    // 37 WHERE-less enumeration calls (LIMIT 100000, no WHERE)
    { rolname: "anon", query: 'SELECT * FROM "public"."sensitive_photos" LIMIT 100000', calls: 37, rows: 37, stats_since: "2025-08-22" },
    // 9405 per-key lookups (WHERE patient_cpf = $1) — NOT enumeration
    { rolname: "anon", query: 'SELECT * FROM "public"."sensitive_photos" WHERE patient_cpf = $1', calls: 9405, rows: 9405, stats_since: "2025-08-22" },
  ];
  const result = processHistoricalAccess(rows, ["sensitive_photos"], { sensitive_photos: "public" });
  assert.equal(result.findings.length, 1, "same role+table+verb -> one group");
  const f = result.findings[0];
  assert.equal(f.check, "anon_historical_enumeration");
  // evidence must have both group totals AND enumeration-specific counts
  assert.equal(f.evidence.calls, 9442, "group total calls (37 + 9405)");
  assert.equal(f.evidence.enumeration_calls, 37, "WHERE-less enumeration calls only");
  assert.equal(f.evidence.enumeration_rows, 37, "WHERE-less enumeration rows only");
  assert.equal(f.evidence.lookup_calls, 9405, "per-key lookup calls");
  // The reason string must NOT claim 9442 WHERE-less — that is the WO-18 bug
  assert.ok(!f.explain.includes("9442 WHERE-less"), "must not claim 9442 WHERE-less calls");
  assert.ok(f.explain.includes("37 WHERE-less"), "must report 37 enumeration calls");
});

// WO-18: authenticated role must never be labelled 'anon' in check id or reason
test("WO-18: authenticated role queries labeled correctly (not anon)", () => {
  const rows = [
    { rolname: "authenticated", query: 'WITH pgrst_source AS (INSERT INTO "public"."sensitive_photos" ("url") VALUES ($1)) SELECT * FROM pgrst_source', calls: 5, rows: 5, stats_since: "2025-08-22" },
  ];
  const result = processHistoricalAccess(rows, ["sensitive_photos"], { sensitive_photos: "public" });
  assert.equal(result.findings.length, 1);
  const f = result.findings[0];
  assert.equal(f.check, "authenticated_historical_write", "check id must use the actual role, not 'anon'");
  assert.ok(!f.explain.includes("Anon"), "reason must not hardcode 'Anon'");
  assert.ok(f.explain.includes("Authenticated"), "reason must use the actual role label");
  assert.equal(f.title, "Historical Authenticated INSERT of public.sensitive_photos");
});

