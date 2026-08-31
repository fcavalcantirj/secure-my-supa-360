import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import {
  classifyNetworkDbConfig,
  processNetworkDb,
  toBool,
  isProduction,
} from "../scripts/checks/network_db.js";
import { normalizeFinding, assembleResult, scanForSecrets } from "../scripts/contract.js";
import { validate } from "../scripts/validate.js";

const SCHEMA_PATH = fileURLToPath(new URL("../schema/finding.schema.json", import.meta.url));
const schema = JSON.parse(readFileSync(SCHEMA_PATH, "utf8"));

// ---------------------------------------------------------------------------
// toBool
// ---------------------------------------------------------------------------

test("toBool: native boolean passes through", () => {
  assert.equal(toBool(true), true);
  assert.equal(toBool(false), false);
});

test("toBool: string 'true'/'false' (Postgres-style) coerced", () => {
  assert.equal(toBool("true"), true);
  assert.equal(toBool("false"), false);
  assert.equal(toBool("TRUE"), true);
  assert.equal(toBool("FALSE"), false);
  assert.equal(toBool(" true "), true);
});

test("toBool: null/undefined -> false", () => {
  assert.equal(toBool(null), false);
  assert.equal(toBool(undefined), false);
});

// ---------------------------------------------------------------------------
// isProduction
// ---------------------------------------------------------------------------

test("isProduction: name with 'prod' / 'production' / 'live' -> true", () => {
  assert.equal(isProduction({ name: "prod-api" }), true);
  assert.equal(isProduction({ name: "production-app" }), true);
  assert.equal(isProduction({ name: "LIVE service" }), true);
});

test("isProduction: dev/staging/test name -> false", () => {
  assert.equal(isProduction({ name: "dev-api" }), false);
  assert.equal(isProduction({ name: "staging-app" }), false);
  assert.equal(isProduction({ name: "test-project" }), false);
  assert.equal(isProduction({ name: "myapp" }), false);
});

test("isProduction: no name -> false", () => {
  assert.equal(isProduction({}), false);
  assert.equal(isProduction({ name: "" }), false);
});

// ---------------------------------------------------------------------------
// classifyNetworkDbConfig — network restrictions
// ---------------------------------------------------------------------------

test("no network restrictions on production project -> db_no_network_restrictions (high)", () => {
  const config = {
    name: "prod-api",
    db_ssl: "true",
    network_restrictions: { enabled: false },
  };
  const findings = classifyNetworkDbConfig(config, "ref123");
  assert.equal(findings.length, 1);
  const f = findings[0];
  assert.equal(f.check, "db_no_network_restrictions");
  assert.equal(f.severity, "high");
  assert.equal(f.confidence, "confirmed");
  assert.equal(f.target, "project:ref123");
  assert.equal(f.evidence.production, true);
  assert.equal(f.evidence.postgres_port_open, true);
  assert.ok(f.fix.management_api_action);
  assert.equal(f.fix.management_api_action.method, "PATCH");
  assert.equal(f.fix.management_api_action.path, "/v1/projects/ref123/network/restrictions");
  assert.deepEqual(f.fix.management_api_action.body, { enabled: true });
  assert.ok(f.fix.dashboard_action, "production projects should have dashboard_action");
});

test("no network restrictions on non-production project -> medium", () => {
  const config = {
    name: "dev-api",
    db_ssl: "true",
    network_restrictions: { enabled: false },
  };
  const findings = classifyNetworkDbConfig(config, "ref456");
  assert.equal(findings.length, 1);
  assert.equal(findings[0].severity, "medium");
  assert.equal(findings[0].evidence.production, false);
  assert.equal(findings[0].fix.dashboard_action, null);
});

test("network restrictions enabled -> no finding", () => {
  const config = {
    name: "prod-api",
    db_ssl: "true",
    network_restrictions: { enabled: true },
  };
  assert.equal(classifyNetworkDbConfig(config, "ref").length, 0);
});

// ---------------------------------------------------------------------------
// classifyNetworkDbConfig — SSL
// ---------------------------------------------------------------------------

test("SSL disabled (db_ssl=false) -> db_ssl_disabled (medium)", () => {
  const config = {
    name: "prod-api",
    db_ssl: "false",
    network_restrictions: { enabled: true },
  };
  const findings = classifyNetworkDbConfig(config, "ref");
  assert.equal(findings.length, 1);
  const f = findings[0];
  assert.equal(f.check, "db_ssl_disabled");
  assert.equal(f.severity, "medium");
  assert.equal(f.confidence, "confirmed");
  assert.equal(f.evidence.db_ssl, "false");
  assert.ok(f.fix.management_api_action);
  assert.equal(f.fix.management_api_action.path, "/v1/projects/ref/network/restrictions");
  assert.deepEqual(f.fix.management_api_action.body, { db_ssl: true });
  assert.ok(f.fix.dashboard_action);
});

test("SSL disabled as boolean false -> flagged", () => {
  const config = { db_ssl: false, network_restrictions: { enabled: true } };
  const findings = classifyNetworkDbConfig(config, "ref");
  const ssl = findings.find((f) => f.check === "db_ssl_disabled");
  assert.ok(ssl, "should flag db_ssl_disabled");
});

test("SSL enabled (db_ssl=true) -> no SSL finding", () => {
  const config = {
    db_ssl: "true",
    network_restrictions: { enabled: true },
  };
  const findings = classifyNetworkDbConfig(config, "ref");
  assert.equal(findings.length, 0);
});

// ---------------------------------------------------------------------------
// classifyNetworkDbConfig — pool mode
// ---------------------------------------------------------------------------

test("pool_mode=session -> db_pool_session_mode (low)", () => {
  const config = {
    db_ssl: "true",
    network_restrictions: { enabled: true },
    pool_mode: "session",
  };
  const findings = classifyNetworkDbConfig(config, "ref");
  assert.equal(findings.length, 1);
  const f = findings[0];
  assert.equal(f.check, "db_pool_session_mode");
  assert.equal(f.severity, "low");
  assert.equal(f.evidence.pool_mode, "session");
  assert.ok(f.fix.management_api_action);
  assert.deepEqual(f.fix.management_api_action.body, { pool_mode: "transaction" });
});

test("pool_mode=transaction -> no finding", () => {
  const config = {
    db_ssl: "true",
    network_restrictions: { enabled: true },
    pool_mode: "transaction",
  };
  assert.equal(classifyNetworkDbConfig(config, "ref").length, 0);
});

// ---------------------------------------------------------------------------
// classifyNetworkDbConfig — multiple issues
// ---------------------------------------------------------------------------

test("all three issues at once -> 3 findings (high, medium, low)", () => {
  const config = {
    name: "prod-app",
    db_ssl: "false",
    network_restrictions: { enabled: false },
    pool_mode: "session",
  };
  const findings = classifyNetworkDbConfig(config, "ref");
  assert.equal(findings.length, 3);
  const checks = findings.map((f) => f.check).sort();
  assert.deepEqual(checks, ["db_no_network_restrictions", "db_pool_session_mode", "db_ssl_disabled"]);
  // Verify severities
  const net = findings.find((f) => f.check === "db_no_network_restrictions");
  const ssl = findings.find((f) => f.check === "db_ssl_disabled");
  const pool = findings.find((f) => f.check === "db_pool_session_mode");
  assert.equal(net.severity, "high"); // production
  assert.equal(ssl.severity, "medium");
  assert.equal(pool.severity, "low");
});

// ---------------------------------------------------------------------------
// classifyNetworkDbConfig — edge cases
// ---------------------------------------------------------------------------

test("null/undefined config -> []", () => {
  assert.deepEqual(classifyNetworkDbConfig(null, "ref"), []);
  assert.deepEqual(classifyNetworkDbConfig(undefined, "ref"), []);
});

test("network_restrictions undefined -> flagged (no restrictions)", () => {
  const config = { db_ssl: "true", name: "prod" };
  const findings = classifyNetworkDbConfig(config, "ref");
  const net = findings.find((f) => f.check === "db_no_network_restrictions");
  assert.ok(net, "should flag absent network_restrictions");
});

test("network_restrictions object without enabled field -> flagged", () => {
  const config = { db_ssl: "true", network_restrictions: {}, name: "dev" };
  const findings = classifyNetworkDbConfig(config, "ref");
  const net = findings.find((f) => f.check === "db_no_network_restrictions");
  assert.ok(net);
  assert.equal(net.severity, "medium"); // non-production
});

// ---------------------------------------------------------------------------
// GOLDEN fixture (spec step 4): no IP allowlist + open direct DB -> medium+
// ---------------------------------------------------------------------------

test("GOLDEN fixture (spec step 4): no IP allowlist + open direct DB -> flagged medium+", () => {
  // Simulates the Management API response for a production project with no
  // network restrictions (IP allowlist disabled).
  const config = {
    id: "proj-123",
    name: "webapp-production",
    region: "us-east-1",
    db_ssl: "false",
    network_restrictions: { enabled: false, egress_enabled: false },
  };
  const findings = processNetworkDb(config, "webapp");
  assert.ok(findings.length >= 1, "should flag at least one issue");
  const netFinding = findings.find((f) => f.check === "db_no_network_restrictions");
  assert.ok(netFinding, "should flag absent network restrictions");
  assert.equal(netFinding.confidence, "confirmed");
  assert.equal(netFinding.evidence.postgres_port_open, true);
  // Severity should be medium+ (production -> high)
  assert.notEqual(netFinding.severity, "low");
  assert.notEqual(netFinding.severity, "info");
});

// ---------------------------------------------------------------------------
// processNetworkDb wrapper
// ---------------------------------------------------------------------------

test("processNetworkDb: passes through to classifyNetworkDbConfig", () => {
  const config = { db_ssl: "false", network_restrictions: { enabled: false }, name: "dev" };
  const findings = processNetworkDb(config, "ref");
  assert.equal(findings.length, 2); // db_no_network_restrictions + db_ssl_disabled
  const checks = findings.map((f) => f.check).sort();
  assert.deepEqual(checks, ["db_no_network_restrictions", "db_ssl_disabled"]);
});

test("processNetworkDb: empty config -> []", () => {
  assert.deepEqual(processNetworkDb({}, "ref"), []);
  assert.deepEqual(processNetworkDb(null, "ref"), []);
});

// ---------------------------------------------------------------------------
// Round-trip: normalize -> assembleResult -> schema valid + no secrets + deterministic
// ---------------------------------------------------------------------------

test("network_db findings round-trip: normalize -> assembleResult -> schema valid + no secrets + deterministic", () => {
  const config = {
    name: "prod-service",
    db_ssl: "false",
    network_restrictions: { enabled: false },
    pool_mode: "session",
  };
  const rawFindings = processNetworkDb(config, "xyz789");
  const normalized = rawFindings.map(normalizeFinding);

  const fixedAt = "2026-08-27T12:00:00.000Z";
  const result = assembleResult({
    project_ref: "xyz789",
    mode: "audit-passive",
    rawFindings: normalized,
    generated_at: fixedAt,
  });

  // 1. Schema validation
  const { valid, errors } = validate(result, schema);
  assert.equal(valid, true, `schema violations: ${JSON.stringify(errors)}`);

  // 2. No secrets in output
  const jsonStr = JSON.stringify(result);
  assert.equal(scanForSecrets(jsonStr).length, 0, "secrets leaked in output");

  // 3. Deterministic ordering — run twice, assert identical
  const opts = {
    project_ref: "xyz789",
    mode: "audit-passive",
    rawFindings: normalized,
    generated_at: fixedAt,
  };
  const json1 = JSON.stringify(assembleResult(opts), null, 2);
  const json2 = JSON.stringify(assembleResult(opts), null, 2);
  assert.equal(json1, json2, "output must be deterministic");

  // Verify finding count and checks
  assert.equal(result.findings.length, 3);
  const checks = result.findings.map((f) => f.check).sort();
  assert.deepEqual(checks, ["db_no_network_restrictions", "db_pool_session_mode", "db_ssl_disabled"]);
});
