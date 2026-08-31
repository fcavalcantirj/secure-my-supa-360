// Tests for scripts/baseline.js (spec entry 28: baseline + diff mode)
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, writeFileSync, mkdirSync, rmSync } from "node:fs";
import { fileURLToPath } from "node:url";

import {
  createBaseline,
  signBaseline,
  verifyBaseline,
  loadBaseline,
  baselineExists,
  saveBaseline,
  diffBaseline,
  buildBaselineDiff,
  computeBaselineExitCode,
} from "../scripts/baseline.js";
import { assembleResult, normalizeFinding, EXIT_CODES } from "../scripts/contract.js";
import { SEVERITY_RANK } from "../scripts/contract.js";

function makeTempDir() {
  const dir = `${process.env.TMPDIR || "/tmp"}/supa360_baseline_${Date.now()}_${Math.random().toString(36).slice(2)}`;
  mkdirSync(dir, { recursive: true });
  return dir;
}

function makeResult(findings) {
  return assembleResult({
    project_ref: "testref01",
    mode: "audit-active",
    rawFindings: findings.map((f) => normalizeFinding(f)),
    generated_at: "2026-08-28T12:00:00.000Z",
  });
}

// --- createBaseline ---

test("createBaseline extracts non-suppressed finding IDs + metadata + signature", () => {
  const result = makeResult([
    { check: "rls_disabled", target: "table_a", severity: "critical", confidence: "confirmed", evidence: {} },
    { check: "storage_bucket_public", target: "bucket:media", severity: "high", confidence: "inferred", evidence: {} },
  ]);
  const baseline = createBaseline(result);
  assert.equal(baseline.schema_version, "1.0");
  assert.equal(baseline.project_ref, "testref01");
  assert.equal(baseline.mode, "audit-active");
  assert.ok(baseline.signature);
  assert.equal(typeof baseline.signature, "string");
  assert.equal(Object.keys(baseline.findings).length, 2);
  const ids = Object.keys(baseline.findings);
  for (const id of ids) {
    const entry = baseline.findings[id];
    assert.ok("check" in entry);
    assert.ok("target" in entry);
    assert.ok("severity" in entry);
    assert.ok("confidence" in entry);
  }
});

test("createBaseline excludes suppressed findings", () => {
  const result = makeResult([
    { check: "rls_disabled", target: "table_a", severity: "critical", confidence: "confirmed", evidence: {} },
    { check: "storage_bucket_public", target: "bucket:media", severity: "high", confidence: "inferred", evidence: {}, suppressed: true },
  ]);
  const baseline = createBaseline(result);
  assert.equal(Object.keys(baseline.findings).length, 1);
  assert.ok(!Object.values(baseline.findings).some((f) => f.target === "bucket:media"));
});

test("createBaseline signature is deterministic (same input → same signature)", () => {
  const result = makeResult([
    { check: "rls_disabled", target: "table_a", severity: "critical", confidence: "confirmed", evidence: {} },
    { check: "storage_bucket_public", target: "bucket:media", severity: "high", confidence: "inferred", evidence: {} },
  ]);
  const b1 = createBaseline(result);
  const b2 = createBaseline(result);
  assert.equal(b1.signature, b2.signature, "same result must produce same baseline signature");
});

// --- signBaseline / verifyBaseline ---

test("verifyBaseline returns true for a valid baseline", () => {
  const result = makeResult([
    { check: "rls_disabled", target: "table_a", severity: "critical", confidence: "confirmed", evidence: {} },
  ]);
  const baseline = createBaseline(result);
  assert.equal(verifyBaseline(baseline), true);
});

test("verifyBaseline returns false for a tampered baseline", () => {
  const result = makeResult([
    { check: "rls_disabled", target: "table_a", severity: "critical", confidence: "confirmed", evidence: {} },
  ]);
  const baseline = createBaseline(result);
  // Tamper: change a finding's severity
  const id = Object.keys(baseline.findings)[0];
  baseline.findings[id].severity = "low";
  assert.equal(verifyBaseline(baseline), false);
});

test("verifyBaseline returns false for a baseline with no signature", () => {
  assert.equal(verifyBaseline({ schema_version: "1.0", project_ref: "x" }), false);
});

// --- saveBaseline / loadBaseline ---

test("saveBaseline + loadBaseline: round-trip preserves findings and verifies", () => {
  const dir = makeTempDir();
  const path = `${dir}/baseline.json`;
  const result = makeResult([
    { check: "rls_disabled", target: "table_a", severity: "critical", confidence: "confirmed", evidence: {} },
    { check: "rpc_confirmed_executable", target: "rpc:get_data", severity: "high", confidence: "confirmed", evidence: {} },
  ]);
  const saved = saveBaseline(path, result);
  assert.ok(baselineExists(path));

  const loaded = loadBaseline(path);
  assert.equal(loaded.signature, saved.signature);
  assert.equal(loaded.project_ref, "testref01");
  assert.equal(Object.keys(loaded.findings).length, 2);
  rmSync(dir, { recursive: true, force: true });
});

test("loadBaseline throws on tampered file", () => {
  const dir = makeTempDir();
  const path = `${dir}/baseline.json`;
  const result = makeResult([
    { check: "rls_disabled", target: "table_a", severity: "critical", confidence: "confirmed", evidence: {} },
  ]);
  saveBaseline(path, result);
  // Tamper on disk
  const raw = JSON.parse(readFileSync(path, "utf8"));
  const id = Object.keys(raw.findings)[0];
  raw.findings[id].severity = "info";
  raw.findings[id].check = "tampered_check";
  writeFileSync(path, JSON.stringify(raw, null, 2));

  assert.throws(() => loadBaseline(path), /signature mismatch/);
  rmSync(dir, { recursive: true, force: true });
});

test("baselineExists returns false for missing file and true for saved", () => {
  const dir = makeTempDir();
  const path = `${dir}/baseline.json`;
  assert.equal(baselineExists(path), false);
  saveBaseline(path, makeResult([]));
  assert.equal(baselineExists(path), true);
  rmSync(dir, { recursive: true, force: true });
});

test("baselineExists returns false for empty result (no findings)", () => {
  const dir = makeTempDir();
  const path = `${dir}/baseline.json`;
  saveBaseline(path, makeResult([]));
  const loaded = loadBaseline(path);
  assert.deepEqual(loaded.findings, {});
  assert.ok(loaded.signature);
  rmSync(dir, { recursive: true, force: true });
});

// --- diffBaseline ---

test("diffBaseline: new finding vs baseline is flagged as regression", () => {
  const baselineResult = makeResult([
    { check: "rls_disabled", target: "table_a", severity: "critical", confidence: "confirmed", evidence: {} },
  ]);
  const baseline = createBaseline(baselineResult);

  const currentResult = makeResult([
    { check: "rls_disabled", target: "table_a", severity: "critical", confidence: "confirmed", evidence: {} },
    { check: "storage_bucket_public", target: "bucket:new_media", severity: "high", confidence: "inferred", evidence: {} },
  ]);

  const diff = diffBaseline(baseline, currentResult);
  assert.equal(diff.newFindings.length, 1);
  assert.equal(diff.newFindings[0].check, "storage_bucket_public");
  assert.equal(diff.existingFindings.length, 1);
  assert.equal(diff.existingFindings[0].check, "rls_disabled");
  assert.equal(diff.removedFindings.length, 0);
});

test("diffBaseline: finding removed from baseline is in removedFindings", () => {
  const baselineResult = makeResult([
    { check: "rls_disabled", target: "table_a", severity: "critical", confidence: "confirmed", evidence: {} },
    { check: "storage_bucket_public", target: "bucket:old_media", severity: "high", confidence: "inferred", evidence: {} },
  ]);
  const baseline = createBaseline(baselineResult);

  const currentResult = makeResult([
    { check: "rls_disabled", target: "table_a", severity: "critical", confidence: "confirmed", evidence: {} },
  ]);

  const diff = diffBaseline(baseline, currentResult);
  assert.equal(diff.newFindings.length, 0);
  assert.equal(diff.existingFindings.length, 1);
  assert.equal(diff.removedFindings.length, 1);
  assert.equal(diff.removedFindings[0].target, "bucket:old_media");
});

test("diffBaseline: suppressed findings are excluded from the diff", () => {
  const baselineResult = makeResult([
    { check: "rls_disabled", target: "table_a", severity: "critical", confidence: "confirmed", evidence: {} },
  ]);
  const baseline = createBaseline(baselineResult);

  const currentResult = makeResult([
    { check: "rls_disabled", target: "table_a", severity: "critical", confidence: "confirmed", evidence: {} },
    { check: "storage_bucket_public", target: "bucket:media", severity: "high", confidence: "inferred", evidence: {}, suppressed: true },
  ]);

  const diff = diffBaseline(baseline, currentResult);
  assert.equal(diff.newFindings.length, 0);
  // suppressed finding is neither new nor existing
  assert.equal(diff.existingFindings.filter((f) => f.target === "bucket:media").length, 0);
});

test("diffBaseline: same findings as baseline = no regressions", () => {
  const result = makeResult([
    { check: "rls_disabled", target: "table_a", severity: "critical", confidence: "confirmed", evidence: {} },
    { check: "storage_bucket_public", target: "bucket:media", severity: "high", confidence: "inferred", evidence: {} },
  ]);
  const baseline = createBaseline(result);
  const diff = diffBaseline(baseline, result);
  assert.equal(diff.newFindings.length, 0);
  assert.equal(diff.existingFindings.length, 2);
  assert.equal(diff.removedFindings.length, 0);
});

// --- buildBaselineDiff ---

test("buildBaselineDiff: reports counts and per-severity regression breakdown", () => {
  const baselineResult = makeResult([
    { check: "rls_disabled", target: "table_a", severity: "critical", confidence: "confirmed", evidence: {} },
  ]);
  const baseline = createBaseline(baselineResult);

  const currentResult = makeResult([
    { check: "rls_disabled", target: "table_a", severity: "critical", confidence: "confirmed", evidence: {} },
    { check: "storage_bucket_public", target: "bucket:b1", severity: "high", confidence: "inferred", evidence: {} },
    { check: "rls_disabled", target: "table_b", severity: "critical", confidence: "inferred", evidence: {} },
  ]);

  const { newFindings, existingFindings, removedFindings } = diffBaseline(baseline, currentResult);
  const bd = buildBaselineDiff(baseline, newFindings, existingFindings, removedFindings);
  assert.equal(bd.new, 2);
  assert.equal(bd.existing, 1);
  assert.equal(bd.removed, 0);
  assert.equal(bd.regression, true);
  assert.equal(bd.regressions_by_severity.critical, 1);
  assert.equal(bd.regressions_by_severity.high, 1);
  assert.equal(bd.regressions_by_severity.medium, 0);
});

test("buildBaselineDiff: no regressions → regression=false", () => {
  const result = makeResult([
    { check: "rls_disabled", target: "table_a", severity: "critical", confidence: "confirmed", evidence: {} },
  ]);
  const baseline = createBaseline(result);
  const { newFindings, existingFindings, removedFindings } = diffBaseline(baseline, result);
  const bd = buildBaselineDiff(baseline, newFindings, existingFindings, removedFindings);
  assert.equal(bd.regression, false);
  assert.equal(bd.new, 0);
  assert.equal(bd.existing, 1);
});

// --- computeBaselineExitCode ---

test("computeBaselineExitCode: new finding at/above fail-on vs baseline → exit 2", () => {
  const baselineResult = makeResult([
    { check: "rls_disabled", target: "table_a", severity: "low", confidence: "confirmed", evidence: {} },
  ]);
  const baseline = createBaseline(baselineResult);

  const currentResult = makeResult([
    { check: "rls_disabled", target: "table_a", severity: "low", confidence: "confirmed", evidence: {} },
    { check: "storage_bucket_public", target: "bucket:new", severity: "high", confidence: "inferred", evidence: {} },
  ]);

  const code = computeBaselineExitCode({
    errors: {}, result: currentResult, baseline, failOn: "high",
  });
  assert.equal(code, EXIT_CODES.FINDINGS, "new high finding vs baseline should exit 2");
});

test("computeBaselineExitCode: new finding below fail-on → exit 0 (CLEAN)", () => {
  const baselineResult = makeResult([]);
  const baseline = createBaseline(baselineResult);

  const currentResult = makeResult([
    { check: "some_low_check", target: "thing", severity: "low", confidence: "inferred", evidence: {} },
  ]);

  const code = computeBaselineExitCode({
    errors: {}, result: currentResult, baseline, failOn: "high",
  });
  assert.equal(code, EXIT_CODES.CLEAN, "low finding below fail-on=high should not trigger");
});

test("computeBaselineExitCode: same findings as baseline → exit 0 (no regressions)", () => {
  const result = makeResult([
    { check: "rls_disabled", target: "table_a", severity: "critical", confidence: "confirmed", evidence: {} },
    { check: "storage_bucket_public", target: "bucket:media", severity: "high", confidence: "inferred", evidence: {} },
  ]);
  const baseline = createBaseline(result);

  const code = computeBaselineExitCode({
    errors: {}, result, baseline, failOn: "high",
  });
  assert.equal(code, EXIT_CODES.CLEAN, "no new findings vs baseline = clean");
});

test("computeBaselineExitCode: confirmedOnly + new inferred finding = CLEAN (not a regression)", () => {
  // Large-inferred-surface case: baseline has 0 confirmed. Current run adds 5 inferred high findings.
  // With confirmedOnly=true, inferred findings don't count as regressions.
  const baselineResult = makeResult([]);
  const baseline = createBaseline(baselineResult);

  const currentResult = makeResult(
    Array.from({ length: 5 }, (_, i) => ({
      check: "rpc_granted_inferred",
      target: `rpc:fn_${i}`,
      severity: "high",
      confidence: "inferred",
      evidence: {},
    }))
  );

  const code = computeBaselineExitCode({
    errors: {}, result: currentResult, baseline, failOn: "high", confirmedOnly: true,
  });
  assert.equal(code, EXIT_CODES.CLEAN, "inferred-only new findings should not regress with confirmedOnly");
});

test("computeBaselineExitCode: confirmedOnly + new CONFIRMED finding = exit 2", () => {
  const baselineResult = makeResult([]);
  const baseline = createBaseline(baselineResult);

  const currentResult = makeResult([
    { check: "rls_disabled", target: "table_leaked", severity: "critical", confidence: "confirmed", evidence: {} },
  ]);

  const code = computeBaselineExitCode({
    errors: {}, result: currentResult, baseline, failOn: "high", confirmedOnly: true,
  });
  assert.equal(code, EXIT_CODES.FINDINGS, "confirmed finding on top of clean baseline = regression");
});

test("computeBaselineExitCode: auth_error takes priority over baseline diff", () => {
  const baseline = createBaseline(makeResult([]));
  const result = makeResult([
    { check: "rls_disabled", target: "t", severity: "critical", confidence: "confirmed", evidence: {} },
  ]);
  const code = computeBaselineExitCode({
    errors: { auth_error: true }, result, baseline, failOn: "high",
  });
  assert.equal(code, EXIT_CODES.AUTH_ERROR);
});

test("computeBaselineExitCode: fail-on=never → CLEAN even with regressions", () => {
  const baseline = createBaseline(makeResult([]));
  const result = makeResult([
    { check: "storage_bucket_public", target: "b", severity: "critical", confidence: "confirmed", evidence: {} },
  ]);
  const code = computeBaselineExitCode({
    errors: {}, result, baseline, failOn: "never",
  });
  assert.equal(code, EXIT_CODES.CLEAN);
});

test("computeBaselineExitCode: no baseline → falls back to standard computeExitCode", () => {
  const result = makeResult([
    { check: "rls_disabled", target: "table_a", severity: "critical", confidence: "confirmed", evidence: {} },
  ]);
  const code = computeBaselineExitCode({
    errors: {}, result, baseline: null, failOn: "high",
  });
  assert.equal(code, EXIT_CODES.FINDINGS, "without baseline, standard gate applies");
});

// --- End-to-end: baseline + add vuln = regression ---

test("e2e: baseline taken on clean fixture, then adding a vuln triggers regression exit 2", () => {
  // Step 1: baseline on a "clean" fixture (only a low-severity known finding)
  const cleanResult = makeResult([
    { check: "no_index", target: "table_a", severity: "low", confidence: "inferred", evidence: {} },
  ]);
  const baseline = createBaseline(cleanResult);

  // Step 2: new run discovers a new critical finding
  const vulnResult = makeResult([
    { check: "no_index", target: "table_a", severity: "low", confidence: "inferred", evidence: {} },
    { check: "rls_disabled", target: "leaked_table", severity: "critical", confidence: "confirmed", evidence: {} },
  ]);

  const code = computeBaselineExitCode({
    errors: {}, result: vulnResult, baseline, failOn: "critical",
  });
  assert.equal(code, EXIT_CODES.FINDINGS, "new critical finding vs baseline should fail");

  const diff = diffBaseline(baseline, vulnResult);
  assert.equal(diff.newFindings.length, 1);
  assert.equal(diff.newFindings[0].severity, "critical");
  assert.equal(diff.existingFindings.length, 1);
});

test("e2e: baseline with divergent-grantee 96 inferred findings, 0 confirmed; new confirmed leak → regression", () => {
  // Baseline: 96 inferred (accepted as non-exploitable), 0 confirmed
  const baselineFindings = Array.from({ length: 96 }, (_, i) => ({
    check: "rpc_granted_inferred",
    target: `rpc:fn_${i}`,
    severity: "high",
    confidence: "inferred",
    evidence: {},
  }));
  const baselineResult = makeResult(baselineFindings);
  const baseline = createBaseline(baselineResult);

  // Current run: same 96 inferred + 1 new confirmed critical
  const currentFindings = [
    ...baselineFindings,
    { check: "rls_disabled", target: "leaked_table", severity: "critical", confidence: "confirmed", evidence: {} },
  ];
  const currentResult = makeResult(currentFindings);

  // With confirmedOnly: the 96 inferred are accepted (in baseline), and only the new confirmed is a regression
  const code = computeBaselineExitCode({
    errors: {}, result: currentResult, baseline, failOn: "high", confirmedOnly: true,
  });
  assert.equal(code, EXIT_CODES.FINDINGS, "new confirmed finding vs baseline should trigger regression");

  // Without confirmedOnly: same result — new confirmed finding is still a regression
  const codeAll = computeBaselineExitCode({
    errors: {}, result: currentResult, baseline, failOn: "high", confirmedOnly: false,
  });
  assert.equal(codeAll, EXIT_CODES.FINDINGS);
});
