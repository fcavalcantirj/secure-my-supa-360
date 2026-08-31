import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import {
  classifyRealtimeTable,
  classifyRealtimeMessages,
  processRealtime,
} from "../scripts/checks/realtime.js";
import { normalizeFinding, assembleResult, scanForSecrets } from "../scripts/contract.js";
import { validate } from "../scripts/validate.js";

const SCHEMA_PATH = fileURLToPath(new URL("../schema/finding.schema.json", import.meta.url));
const schema = JSON.parse(readFileSync(SCHEMA_PATH, "utf8"));

// ---------------------------------------------------------------------------
// classifyRealtimeTable
// ---------------------------------------------------------------------------

test("classifyRealtimeTable: published table with RLS off -> finding (inferred)", () => {
  const f = classifyRealtimeTable({ table_name: "messages", rls_enabled: false, in_publication: true });
  assert.equal(f.length, 1);
  assert.equal(f[0].check, "realtime_publication_no_rls");
  assert.equal(f[0].severity, "critical");
  assert.equal(f[0].confidence, "inferred");
  assert.equal(f[0].target, "table:messages");
  assert.equal(f[0].evidence.rls_enabled, false);
  assert.equal(f[0].evidence.in_publication, "supabase_realtime");
});

test("classifyRealtimeTable: published table with RLS on -> no finding", () => {
  assert.deepEqual(
    classifyRealtimeTable({ table_name: "messages", rls_enabled: true, in_publication: true }),
    []
  );
});

test("classifyRealtimeTable: table not in publication -> no finding", () => {
  assert.deepEqual(
    classifyRealtimeTable({ table_name: "messages", rls_enabled: false, in_publication: false }),
    []
  );
});

test("classifyRealtimeTable: probe confirms -> confidence 'confirmed'", () => {
  const probe = { status: 200, rowCount: 42, bytes: 512 };
  const f = classifyRealtimeTable({ table_name: "chats", rls_enabled: false, in_publication: true }, probe);
  assert.equal(f.length, 1);
  assert.equal(f[0].confidence, "confirmed");
  assert.equal(f[0].evidence.probe.status, 200);
  assert.equal(f[0].evidence.probe.row_count, 42);
  assert.equal(f[0].evidence.probe.bytes, 512);
});

test("classifyRealtimeTable: probe blocked (401) -> confidence 'inferred'", () => {
  const probe = { status: 401, rowCount: 0, bytes: 0 };
  const f = classifyRealtimeTable({ table_name: "chats", rls_enabled: false, in_publication: true }, probe);
  assert.equal(f.length, 1);
  assert.equal(f[0].confidence, "inferred");
});

test("classifyRealtimeTable: null/invalid -> []", () => {
  assert.deepEqual(classifyRealtimeTable(null), []);
  assert.deepEqual(classifyRealtimeTable({}), []);
  assert.deepEqual(classifyRealtimeTable({ rls_enabled: false }), []);
});

// ---------------------------------------------------------------------------
// classifyRealtimeMessages
// ---------------------------------------------------------------------------

test("classifyRealtimeMessages: anon select + no policies -> realtime_broadcast_anon_read (high)", () => {
  const config = { rls_enabled: false, anon_select: true, has_policies: false };
  const f = classifyRealtimeMessages(config);
  assert.equal(f.length, 1);
  assert.equal(f[0].check, "realtime_broadcast_anon_read");
  assert.equal(f[0].severity, "high");
  assert.equal(f[0].confidence, "inferred");
  assert.equal(f[0].target, "table:realtime.messages");
});

test("classifyRealtimeMessages: anon insert + no policies -> realtime_broadcast_anon_write (critical)", () => {
  const config = { rls_enabled: false, anon_insert: true, anon_select: false, has_policies: false };
  const f = classifyRealtimeMessages(config);
  assert.equal(f.length, 1);
  assert.equal(f[0].check, "realtime_broadcast_anon_write");
  assert.equal(f[0].severity, "critical");
  assert.equal(f[0].confidence, "inferred");
});

test("classifyRealtimeMessages: both anon select + insert -> two findings", () => {
  const config = { rls_enabled: false, anon_select: true, anon_insert: true, has_policies: false };
  const f = classifyRealtimeMessages(config);
  assert.equal(f.length, 2);
  const checks = f.map((x) => x.check).sort();
  assert.deepEqual(checks, ["realtime_broadcast_anon_read", "realtime_broadcast_anon_write"]);
});

test("classifyRealtimeMessages: RLS on + has policies + anon select -> no finding (policy-gated)", () => {
  const config = { rls_enabled: true, anon_select: true, has_policies: true };
  assert.deepEqual(classifyRealtimeMessages(config), []);
});

test("classifyRealtimeMessages: RLS on + no policies + anon select -> finding (unprotected)", () => {
  const config = { rls_enabled: true, anon_select: true, has_policies: false };
  const f = classifyRealtimeMessages(config);
  assert.equal(f.length, 1);
  assert.equal(f[0].check, "realtime_broadcast_anon_read");
});

test("classifyRealtimeMessages: RLS on + no policies -> severity downgraded to low (defense-in-depth)", () => {
  // RLS ON + 0 policies denies all access — safe but unintended.
  // Downgrade from high/critical to low, like rls_no_policies_with_anon_grants.
  const readConfig = { rls_enabled: true, anon_select: true, has_policies: false };
  const readFindings = classifyRealtimeMessages(readConfig);
  assert.equal(readFindings.length, 1);
  assert.equal(readFindings[0].check, "realtime_broadcast_anon_read");
  assert.equal(readFindings[0].severity, "low", "RLS+0-policies read -> low, not high");

  const writeConfig = { rls_enabled: true, anon_insert: true, has_policies: false };
  const writeFindings = classifyRealtimeMessages(writeConfig);
  assert.equal(writeFindings.length, 1);
  assert.equal(writeFindings[0].check, "realtime_broadcast_anon_write");
  assert.equal(writeFindings[0].severity, "low", "RLS+0-policies write -> low, not critical");
});

test("classifyRealtimeMessages: RLS off + no policies -> normal severity (not downgraded)", () => {
  // RLS OFF means anon grants are a real leak — keep high/critical.
  const config = { rls_enabled: false, anon_select: true, anon_insert: true, has_policies: false };
  const f = classifyRealtimeMessages(config);
  assert.equal(f.length, 2);
  assert.equal(f.find((x) => x.check === "realtime_broadcast_anon_read").severity, "high");
  assert.equal(f.find((x) => x.check === "realtime_broadcast_anon_write").severity, "critical");
});

test("classifyRealtimeMessages: anon has no access -> no findings", () => {
  const config = { rls_enabled: false, anon_select: false, anon_insert: false, has_policies: true };
  assert.deepEqual(classifyRealtimeMessages(config), []);
});

test("classifyRealtimeMessages: null/undefined -> []", () => {
  assert.deepEqual(classifyRealtimeMessages(null), []);
  assert.deepEqual(classifyRealtimeMessages(undefined), []);
});

// ---------------------------------------------------------------------------
// processRealtime
// ---------------------------------------------------------------------------

test("processRealtime: aggregates realtime tables + messages findings", async () => {
  const data = {
    realtimeTables: [
      { table_name: "chats", rls_enabled: false, in_publication: true },
    ],
    realtimeMessages: {
      rls_enabled: false,
      anon_select: true,
      anon_insert: false,
      has_policies: false,
    },
  };
  const findings = await processRealtime(data, "ref");
  assert.equal(findings.length, 2);
  const checks = findings.map((f) => f.check).sort();
  assert.deepEqual(checks, ["realtime_broadcast_anon_read", "realtime_publication_no_rls"]);
});

test("processRealtime: empty data -> []", async () => {
  assert.deepEqual(await processRealtime({}, "ref"), []);
  assert.deepEqual(await processRealtime({ realtimeTables: [], realtimeMessages: null }, "ref"), []);
});

test("processRealtime: uses probeFn for confirmed confidence", async () => {
  const data = {
    realtimeTables: [
      { table_name: "chats", rls_enabled: false, in_publication: true },
    ],
    realtimeMessages: null,
  };
  const probeFn = async (tableName) => ({ status: 200, rowCount: 5, bytes: 128 });
  const findings = await processRealtime(data, "ref", probeFn);
  assert.equal(findings.length, 1);
  assert.equal(findings[0].confidence, "confirmed");
});

// ---------------------------------------------------------------------------
// GOLDEN fixtures
// ---------------------------------------------------------------------------

test("GOLDEN: published table without RLS fires (inferred)", async () => {
  const data = {
    realtimeTables: [
      { table_name: "orders", rls_enabled: false, in_publication: true },
    ],
    realtimeMessages: null,
  };
  const findings = await processRealtime(data, "ref");
  assert.equal(findings.length, 1);
  assert.equal(findings[0].check, "realtime_publication_no_rls");
  assert.equal(findings[0].severity, "critical");
});

test("GOLDEN: anon broadcast write fires (critical)", async () => {
  const data = {
    realtimeTables: [],
    realtimeMessages: {
      rls_enabled: false,
      anon_select: true,
      anon_insert: true,
      has_policies: false,
    },
  };
  const findings = await processRealtime(data, "ref");
  const critical = findings.find((f) => f.check === "realtime_broadcast_anon_write");
  assert.ok(critical, "should flag anon broadcast write");
  assert.equal(critical.severity, "critical");
});

// ---------------------------------------------------------------------------
// Round-trip: normalize -> assembleResult -> schema valid + no secrets + deterministic
// ---------------------------------------------------------------------------

test("realtime findings round-trip: normalize -> assembleResult -> schema valid + no secrets + deterministic", async () => {
  const data = {
    realtimeTables: [
      { table_name: "secret_table", rls_enabled: false, in_publication: true },
    ],
    realtimeMessages: {
      rls_enabled: false,
      anon_select: true,
      anon_insert: true,
      has_policies: false,
    },
  };
  const rawFindings = await processRealtime(data, "ref", null);
  const normalized = rawFindings.map(normalizeFinding);

  const fixedAt = "2026-08-07T12:00:00.000Z";
  const opts = {
    project_ref: "ref",
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
  assert.equal(result.findings.length, 3);
  const checks = result.findings.map((f) => f.check).sort();
  assert.deepEqual(checks, ["realtime_broadcast_anon_read", "realtime_broadcast_anon_write", "realtime_publication_no_rls"]);
});
