import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import {
  classifyExtension,
  classifyCronJob,
  classifyVaultGrants,
  processExtensionsCron,
  scanCronCommandForSecrets,
  isRiskyExtension,
  getVulnerableVersion,
  toBool,
} from "../scripts/checks/extensions_cron.js";
import { normalizeFinding, assembleResult, scanForSecrets } from "../scripts/contract.js";
import { validate } from "../scripts/validate.js";

const SCHEMA_PATH = fileURLToPath(new URL("../schema/finding.schema.json", import.meta.url));
const schema = JSON.parse(readFileSync(SCHEMA_PATH, "utf8"));

// ---------------------------------------------------------------------------
// isRiskyExtension
// ---------------------------------------------------------------------------

test("isRiskyExtension: http and pg_net are risky", () => {
  assert.equal(isRiskyExtension("http"), true);
  assert.equal(isRiskyExtension("pg_net"), true);
});

test("isRiskyExtension: safe extensions are not risky", () => {
  assert.equal(isRiskyExtension("uuid-ossp"), false);
  assert.equal(isRiskyExtension("pgcrypto"), false);
  assert.equal(isRiskyExtension("supabase_functions"), false);
  assert.equal(isRiskyExtension("extension_unavailable"), false);
});

// ---------------------------------------------------------------------------
// getVulnerableVersion
// ---------------------------------------------------------------------------

test("getVulnerableVersion: known-vulnerable pg_net version -> returns cve id", () => {
  const result = getVulnerableVersion("pg_net", "0.0.3");
  assert.ok(result);
  assert.ok(result.includes("pg_net"));
});

test("getVulnerableVersion: safe pg_net version -> null", () => {
  assert.equal(getVulnerableVersion("pg_net", "0.0.10"), null);
  assert.equal(getVulnerableVersion("pg_net", "1.0.0"), null);
});

test("getVulnerableVersion: non-risky extension -> null", () => {
  assert.equal(getVulnerableVersion("uuid-ossp", "1.1"), null);
  assert.equal(getVulnerableVersion(null, "1.0"), null);
  assert.equal(getVulnerableVersion("http", null), null);
});

// ---------------------------------------------------------------------------
// scanCronCommandForSecrets
// ---------------------------------------------------------------------------

test("scanCronCommandForSecrets: detects bearer token", () => {
  const cmd = "SELECT net.http_post('https://api.example.com/webhook', 'Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OWFiY2RlZiIsImV4cCI6OTk5OTk5OTk5OX0.dFoiJ8xK7z2q3pP4q0y8z0', '{}');";
  const secrets = scanCronCommandForSecrets(cmd);
  assert.ok(secrets.length > 0, "should detect secrets in command");
  assert.ok(secrets.some((s) => s.name === "bearer_token"));
});

test("scanCronCommandForSecrets: detects Supabase PAT", () => {
  const cmd = "SELECT net.http_post('https://api.example.com', 'Bearer sbp_abcdefghijklmnopqrstuvwxyz1234', '{}');";
  const secrets = scanCronCommandForSecrets(cmd);
  assert.ok(secrets.some((s) => s.name === "supabase_pat"));
});

test("scanCronCommandForSecrets: detects DB connection string", () => {
  const cmd = "SELECT net.http_post('https://hooks.example.com', '{}', {}); -- conn: postgres://user:secretpass@db.supabase.co:5432/postgres";
  const secrets = scanCronCommandForSecrets(cmd);
  assert.ok(secrets.some((s) => s.name === "db_connstring"));
});

test("scanCronCommandForSecrets: clean command -> []", () => {
  const cmd = "SELECT net.http_post('https://api.example.com/webhook', '{}', '{}');";
  assert.deepEqual(scanCronCommandForSecrets(cmd), []);
});

test("scanCronCommandForSecrets: null/empty -> []", () => {
  assert.deepEqual(scanCronCommandForSecrets(null), []);
  assert.deepEqual(scanCronCommandForSecrets(""), []);
  assert.deepEqual(scanCronCommandForSecrets(undefined), []);
});

// ---------------------------------------------------------------------------
// classifyExtension
// ---------------------------------------------------------------------------

test("risky extension (http) installed -> extension_risky_installed (medium)", () => {
  const findings = classifyExtension({ extname: "http", extversion: "1.1.5" });
  assert.equal(findings.length, 1);
  const f = findings[0];
  assert.equal(f.check, "extension_risky_installed");
  assert.equal(f.severity, "medium");
  assert.equal(f.confidence, "confirmed");
  assert.equal(f.target, "extension:http");
  assert.equal(f.evidence.extname, "http");
  assert.equal(f.fix.sql[0], "DROP EXTENSION IF EXISTS http;");
});

test("pg_net installed (safe version) -> only risky finding, no vuln", () => {
  const findings = classifyExtension({ extname: "pg_net", extversion: "0.0.10" });
  assert.equal(findings.length, 1);
  assert.equal(findings[0].check, "extension_risky_installed");
});

test("pg_net known-vulnerable version -> both risky + known_vulnerable findings", () => {
  const findings = classifyExtension({ extname: "pg_net", extversion: "0.0.3" });
  assert.equal(findings.length, 2);
  const checks = findings.map((f) => f.check).sort();
  assert.deepEqual(checks, ["extension_known_vulnerable", "extension_risky_installed"]);
  const vuln = findings.find((f) => f.check === "extension_known_vulnerable");
  assert.equal(vuln.severity, "high");
  assert.ok(vuln.evidence.cve);
});

test("non-risky extension (pgcrypto) -> no findings", () => {
  assert.equal(classifyExtension({ extname: "pgcrypto", extversion: "1.4" }).length, 0);
});

test("null/invalid extension -> []", () => {
  assert.deepEqual(classifyExtension(null), []);
  assert.deepEqual(classifyExtension({}), []);
  assert.deepEqual(classifyExtension({ extversion: "1.0" }), []);
});

// ---------------------------------------------------------------------------
// classifyCronJob
// ---------------------------------------------------------------------------

test("cron job with embedded secret -> cron_job_embedded_secret (high)", () => {
  const job = {
    jobid: 1,
    schedule: "* * * * *",
    command: "SELECT net.http_post('https://api.example.com', '{}', '{\"Authorization\": \"Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OWFiY2RlZiIsImV4cCI6OTk5OTk5OTk5OX0.dFoiJ8xK7z2q3pP4q0y8z0\"}');",
    database: "postgres",
    username: "supabase_admin",
  };
  const findings = classifyCronJob(job);
  assert.equal(findings.length, 1);
  const f = findings[0];
  assert.equal(f.check, "cron_job_embedded_secret");
  assert.equal(f.severity, "high");
  assert.equal(f.confidence, "confirmed");
  assert.equal(f.target, "cron:1");
  assert.equal(f.evidence.uses_http_post, true);
  assert.ok(f.evidence.secrets_found.length > 0);
  assert.ok(f.evidence.command_preview);
  // command_preview must not contain raw secrets
  assert.ok(!f.evidence.command_preview.includes("eyJhbGci"), "command_preview must redact JWT");
  assert.ok(f.fix.sql.length > 0);
});

test("command_preview is redacted by scanForSecrets (no inline token leaks)", () => {
  const job = {
    jobid: 99,
    schedule: "0 * * * *",
    command:
      "SELECT net.http_post('https://api.example.com', '{}', '{\"Authorization\": \"Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OWFiY2RlZiIsImV4cCI6OTk5OTk5OTk5OX0.dFoiJ8xK7z2q3pP4q0y8z0\"}'); " +
      "SELECT net.http_post('https://hooks.slack.com', '{}', '{}', 'token=sbp_abcdefghijklmnopqrst');",
    database: "postgres",
    username: "admin",
  };
  const findings = classifyCronJob(job);
  assert.equal(findings.length, 1);
  const preview = findings[0].evidence.command_preview;
  // scanForSecrets must find ZERO secrets in the redacted command_preview
  assert.equal(scanForSecrets(preview).length, 0, "command_preview must not leak secrets");
  assert.ok(!preview.includes("eyJhbGci"), "JWT must be redacted from command_preview");
  assert.ok(!preview.includes("sbp_abcdefghijklmnopqrst"), "PAT must be redacted from command_preview");
});

test("cron job without secrets -> no finding", () => {
  const job = {
    jobid: 2,
    schedule: "0 1 * * *",
    command: "SELECT net.http_post('https://api.example.com/webhook', '{}', '{}');",
    database: "postgres",
    username: "supabase_admin",
  };
  assert.equal(classifyCronJob(job).length, 0);
});

test("null/invalid cron job -> []", () => {
  assert.deepEqual(classifyCronJob(null), []);
  assert.deepEqual(classifyCronJob({}), []);
});

// ---------------------------------------------------------------------------
// classifyVaultGrants
// ---------------------------------------------------------------------------

test("vault readable by anon -> vault_decrypted_secrets_exposed (critical)", () => {
  const findings = classifyVaultGrants({ anon_select: true, auth_select: false }, "ref123");
  assert.equal(findings.length, 1);
  const f = findings[0];
  assert.equal(f.check, "vault_decrypted_secrets_exposed");
  assert.equal(f.severity, "critical");
  assert.equal(f.confidence, "confirmed");
  assert.equal(f.target, "project:ref123");
  assert.equal(f.evidence.anon_select, true);
  assert.equal(f.evidence.auth_select, false);
  assert.equal(f.fix.sql[0], "REVOKE SELECT ON TABLE vault.decrypted_secrets FROM anon;");
  assert.equal(f.fix.sql.length, 1, "should only revoke from anon (auth_select=false)");
  assert.equal(f.fix.rollback_sql[0], "GRANT SELECT ON TABLE vault.decrypted_secrets TO anon;");
  assert.equal(f.fix.rollback_sql.length, 1, "rollback should only restore to anon");
});

test("vault readable by authenticated -> also flagged", () => {
  const findings = classifyVaultGrants({ anon_select: false, auth_select: true }, "ref");
  assert.equal(findings.length, 1);
  assert.equal(findings[0].evidence.auth_select, true);
});

test("vault NOT readable by anon/auth -> no finding", () => {
  assert.equal(classifyVaultGrants({ anon_select: false, auth_select: false }, "ref").length, 0);
});

test("vault grants null/undefined -> no finding", () => {
  assert.deepEqual(classifyVaultGrants(null, "ref"), []);
  assert.deepEqual(classifyVaultGrants(undefined, "ref"), []);
});

// ---------------------------------------------------------------------------
// toBool
// ---------------------------------------------------------------------------

test("toBool: handles boolean + string coercion", () => {
  assert.equal(toBool(true), true);
  assert.equal(toBool(false), false);
  assert.equal(toBool("true"), true);
  assert.equal(toBool("false"), false);
  assert.equal(toBool(undefined), false);
});

// ---------------------------------------------------------------------------
// processExtensionsCron
// ---------------------------------------------------------------------------

test("processExtensionsCron: aggregates findings from extensions + cron + vault", () => {
  const data = {
    extensions: [
      { extname: "http", extversion: "1.1.5" },
      { extname: "pgcrypto", extversion: "1.4" },
    ],
    cronJobs: [
      { jobid: 5, schedule: "* * * * *", command: "SELECT 1;", database: "postgres", username: "admin" },
      { jobid: 6, schedule: "0 * * * *", command: "SELECT net.http_post('https://x.com', '{}', 'token=sbp_abcdefghijklmnopqrst');", database: "postgres", username: "admin" },
    ],
    vaultGrants: { anon_select: true, auth_select: false },
  };
  const findings = processExtensionsCron(data, "ref");
  // http extension (risky) + cron job 6 (secret) + vault (exposed) = 3 findings
  assert.equal(findings.length, 3);
  const checks = findings.map((f) => f.check).sort();
  assert.deepEqual(checks, ["cron_job_embedded_secret", "extension_risky_installed", "vault_decrypted_secrets_exposed"]);
});

test("processExtensionsCron: empty data -> []", () => {
  assert.deepEqual(processExtensionsCron({}, "ref"), []);
  assert.deepEqual(processExtensionsCron({ extensions: [], cronJobs: [], vaultGrants: null }, "ref"), []);
});

// ---------------------------------------------------------------------------
// GOLDEN fixture (spec step 4): cron job with inline bearer token -> flagged
// ---------------------------------------------------------------------------

test("GOLDEN fixture (spec step 4): cron job with inline bearer token is flagged", () => {
  const data = {
    extensions: [{ extname: "pg_net", extversion: "0.0.10" }],
    cronJobs: [
      {
        jobid: 42,
        schedule: "*/5 * * * *",
        command: "SELECT net.http_post('https://hooks.slack.com/services/T000/B000/XXX', '{}', '{}', '{\"Authorization\": \"Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OWFiY2RlZiJ9.dFoiJ8xK7z2q3pP4'}');",
        database: "postgres",
        username: "supabase_admin",
      },
    ],
  };
  const findings = processExtensionsCron(data, "myref");
  assert.ok(findings.length > 0, "should flag the cron job with embedded secret");
  const cronFinding = findings.find((f) => f.check === "cron_job_embedded_secret");
  assert.ok(cronFinding, "should have cron_job_embedded_secret finding");
  assert.equal(cronFinding.severity, "high");
  assert.equal(cronFinding.target, "cron:42");
  assert.equal(cronFinding.evidence.uses_http_post, true);
  assert.ok(cronFinding.evidence.secrets_found.length > 0);
});

// ---------------------------------------------------------------------------
// Round-trip: normalize -> assembleResult -> schema valid + no secrets + deterministic
// ---------------------------------------------------------------------------

test("extensions_cron findings round-trip: normalize -> assembleResult -> schema valid + no secrets + deterministic", () => {
  const data = {
    extensions: [{ extname: "http", extversion: "1.1.5" }],
    cronJobs: [
      {
        jobid: 1,
        schedule: "* * * * *",
        command: "SELECT net.http_post('https://api.example.com', '{}', '{\"key\": \"sbp_abcdefghijklmnopqrst\"}');",
        database: "postgres",
        username: "admin",
      },
    ],
    vaultGrants: { anon_select: true, auth_select: false },
  };
  const rawFindings = processExtensionsCron(data, "xyz789");
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
  assert.equal(result.findings.length, 3);
  const checks = result.findings.map((f) => f.check).sort();
  assert.deepEqual(checks, ["cron_job_embedded_secret", "extension_risky_installed", "vault_decrypted_secrets_exposed"]);
});
