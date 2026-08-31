// Tests for scripts/suppress.js (spec entry 29: suppression / allowlist)
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, mkdirSync, writeFileSync, rmSync } from "node:fs";

import {
  loadSuppressions,
  applySuppressions,
  checkStaleSuppressions,
  suppressionSummary,
} from "../scripts/suppress.js";
import { normalizeFinding, assembleResult } from "../scripts/contract.js";

function makeTempDir() {
  const dir = `${process.env.TMPDIR || "/tmp"}/supa360_test_${Date.now()}_${Math.random().toString(36).slice(2)}`;
  mkdirSync(dir, { recursive: true });
  return dir;
}

// === loadSuppressions ===

test("loadSuppressions: returns entries from a valid .supa360.json", () => {
  const dir = makeTempDir();
  writeFileSync(`${dir}/.supa360.json`, JSON.stringify({
    suppressions: [
      { target: "bucket:media", reason: "public marketing bucket" },
      { target: "table:blog_posts", reason: "public content" },
    ],
  }));
  const result = loadSuppressions(dir);
  assert.equal(result.length, 2);
  assert.equal(result[0].target, "bucket:media");
  assert.equal(result[0].reason, "public marketing bucket");
  rmSync(dir, { recursive: true, force: true });
});

test("loadSuppressions: returns [] when .supa360.json missing", () => {
  const result = loadSuppressions("/nonexistent/path/12345");
  assert.deepEqual(result, []);
});

test("loadSuppressions: returns [] on invalid JSON", () => {
  const dir = makeTempDir();
  writeFileSync(`${dir}/.supa360.json`, "{ broken json }");
  assert.deepEqual(loadSuppressions(dir), []);
  rmSync(dir, { recursive: true, force: true });
});

test("loadSuppressions: returns [] when no suppressions key", () => {
  const dir = makeTempDir();
  writeFileSync(`${dir}/.supa360.json`, JSON.stringify({ version: 1 }));
  assert.deepEqual(loadSuppressions(dir), []);
  rmSync(dir, { recursive: true, force: true });
});

test("loadSuppressions: defaults to cwd when no dir given", () => {
  const result = loadSuppressions();
  assert.ok(Array.isArray(result));
});

// === applySuppressions ===

test("applySuppressions: suppresses finding by target (no check filter)", () => {
  const findings = [
    { target: "bucket:media", check: "storage_bucket_public", severity: "high" },
    { target: "table:users", check: "rls_disabled", severity: "critical" },
  ];
  const suppressions = [
    { target: "bucket:media", reason: "public by design" },
  ];
  const result = applySuppressions(findings, suppressions);

  assert.equal(result[0].suppressed, true);
  assert.equal(result[0].suppressed_reason, "public by design");
  assert.equal(result[1].suppressed, undefined);
});

test("applySuppressions: check-specific suppression only suppresses matching check", () => {
  const findings = [
    { target: "table:posts", check: "rls_disabled", severity: "critical" },
    { target: "table:posts", check: "rls_permissive_policy", severity: "high" },
  ];
  const suppressions = [
    { target: "table:posts", check: "rls_disabled", reason: "intentionally public" },
  ];
  const result = applySuppressions(findings, suppressions);

  assert.equal(result[0].suppressed, true);
  assert.equal(result[0].suppressed_reason, "intentionally public");
  assert.equal(result[1].suppressed, undefined);
});

test("applySuppressions: generic (no check) suppression suppresses all findings for target", () => {
  const findings = [
    { target: "rpc:get_config", check: "rpc_confirmed_executable", severity: "high" },
    { target: "rpc:get_config", check: "function_secdef_missing_auth_check", severity: "critical" },
  ];
  const suppressions = [
    { target: "rpc:get_config", reason: "public endpoint" },
  ];
  const result = applySuppressions(findings, suppressions);

  assert.equal(result[0].suppressed, true);
  assert.equal(result[1].suppressed, true);
});

test("applySuppressions: no suppressions -> findings unchanged", () => {
  const findings = [
    { target: "bucket:media", check: "storage_bucket_public", severity: "high" },
  ];
  const result = applySuppressions(findings, []);
  assert.equal(result[0].suppressed, undefined);
  // Same object reference (no copy) when no suppressions match
  assert.equal(result[0], findings[0]);
});

test("applySuppressions: empty suppressions array -> findings unchanged", () => {
  const findings = [{ target: "bucket:media", check: "storage_bucket_public", severity: "high" }];
  const result = applySuppressions(findings, []);
  assert.equal(result.length, 1);
  assert.equal(result[0].suppressed, undefined);
});

test("applySuppressions: does not mutate original findings", () => {
  const findings = [
    { target: "bucket:media", check: "storage_bucket_public", severity: "high", suppressed: false },
  ];
  const suppressions = [{ target: "bucket:media", reason: "intentional" }];
  const result = applySuppressions(findings, suppressions);

  assert.equal(result[0].suppressed, true);
  assert.equal(findings[0].suppressed, false);
  assert.notEqual(result[0], findings[0]);
});

test("applySuppressions: non-matching suppression -> no change", () => {
  const findings = [{ target: "bucket:other", check: "storage_bucket_public", severity: "high" }];
  const suppressions = [{ target: "bucket:media", reason: "intentional" }];
  const result = applySuppressions(findings, suppressions);
  assert.equal(result[0].suppressed, undefined);
});

// === checkStaleSuppressions ===

test("checkStaleSuppressions: reports allowlisted targets with no matching finding", () => {
  const findings = [
    { target: "bucket:media", suppressed: false },
  ];
  const suppressions = [
    { target: "bucket:media", reason: "ok" },
    { target: "bucket:nonexistent", reason: "stale" },
  ];
  const stale = checkStaleSuppressions(findings, suppressions);
  assert.equal(stale.length, 1);
  assert.equal(stale[0].target, "bucket:nonexistent");
});

test("checkStaleSuppressions: returns [] when all suppressions match findings", () => {
  const findings = [
    { target: "bucket:media" },
    { target: "table:posts" },
  ];
  const suppressions = [
    { target: "bucket:media", reason: "ok" },
    { target: "table:posts", reason: "ok" },
  ];
  assert.deepEqual(checkStaleSuppressions(findings, suppressions), []);
});

test("checkStaleSuppressions: returns [] with no suppressions", () => {
  assert.deepEqual(checkStaleSuppressions([], []), []);
});

test("checkStaleSuppressions: suppressed findings still count for freshness", () => {
  const findings = [
    { target: "bucket:media", suppressed: true, suppressed_reason: "ok" },
  ];
  const suppressions = [
    { target: "bucket:media", reason: "ok" },
  ];
  assert.deepEqual(checkStaleSuppressions(findings, suppressions), []);
});

// === suppressionSummary ===

test("suppressionSummary: counts suppressed findings and groups by check", () => {
  const findings = [
    { check: "storage_bucket_public", suppressed: true },
    { check: "rls_disabled", suppressed: true },
    { check: "storage_bucket_public", suppressed: false },
  ];
  const summary = suppressionSummary(findings);
  assert.equal(summary.suppressed, 2);
  assert.equal(summary.suppressed_by_check["storage_bucket_public"], 1);
  assert.equal(summary.suppressed_by_check["rls_disabled"], 1);
});

// === Integration: suppression + contract ===

test("applySuppressions + normalizeFinding + assembleResult: suppressed findings pass schema + are excluded from fail-gate", () => {
  const rawFindings = [
    {
      check: "storage_bucket_public",
      target: "bucket:content-media",
      severity: "high",
      confidence: "inferred",
      evidence: {},
      fix: { sql: ["UPDATE storage.buckets SET public = false WHERE id = 'media';"], rollback_sql: ["UPDATE storage.buckets SET public = true WHERE id = 'media';"], requires_service_role: false },
    },
    {
      check: "rls_disabled",
      target: "secret_table",
      severity: "critical",
      confidence: "confirmed",
      evidence: {},
      fix: { sql: ["ALTER TABLE secret_table ENABLE ROW LEVEL SECURITY;"], rollback_sql: ["ALTER TABLE secret_table DISABLE ROW LEVEL SECURITY;"], requires_service_role: false },
    },
  ];

  const normalized = rawFindings.map(normalizeFinding);
  const suppressions = [{ target: "bucket:content-media", reason: "intentionally public marketing media" }];
  const suppressed = applySuppressions(normalized, suppressions);

  const bucketFinding = suppressed.find((f) => f.target === "bucket:content-media");
  assert.equal(bucketFinding.suppressed, true);
  assert.equal(bucketFinding.suppressed_reason, "intentionally public marketing media");

  const rlsFinding = suppressed.find((f) => f.check === "rls_disabled");
  assert.equal(rlsFinding.suppressed, false);

  const result = assembleResult({
    project_ref: "test-ref",
    mode: "audit-active",
    rawFindings: suppressed,
    generated_at: "2026-08-27T12:00:00.000Z",
  });

  assert.equal(result.findings.length, 2);
  assert.equal(result.summary.suppressed, 1);

  const stale = checkStaleSuppressions(suppressed, suppressions);
  assert.equal(stale.length, 0);
});

test("applySuppressions: non-allowlisted public bucket still fails the gate", () => {
  const rawFindings = [
    {
      check: "storage_bucket_public",
      target: "bucket:allowed-media",
      severity: "high",
      confidence: "inferred",
      evidence: {},
      fix: { sql: ["UPDATE storage.buckets SET public = false WHERE id = 'allowed-media';"], rollback_sql: ["UPDATE storage.buckets SET public = true WHERE id = 'allowed-media';"], requires_service_role: false },
    },
    {
      check: "storage_bucket_public",
      target: "bucket:secret-data",
      severity: "high",
      confidence: "inferred",
      evidence: {},
      fix: { sql: ["UPDATE storage.buckets SET public = false WHERE id = 'secret-data';"], rollback_sql: ["UPDATE storage.buckets SET public = true WHERE id = 'secret-data';"], requires_service_role: false },
    },
  ];

  const normalized = rawFindings.map(normalizeFinding);
  const suppressions = [{ target: "bucket:allowed-media", reason: "public by design" }];
  const result = applySuppressions(normalized, suppressions);

  const allowed = result.find((f) => f.target === "bucket:allowed-media");
  assert.equal(allowed.suppressed, true);

  const secret = result.find((f) => f.target === "bucket:secret-data");
  assert.equal(secret.suppressed, false);
  assert.equal(secret.suppressed_reason, null);
});
