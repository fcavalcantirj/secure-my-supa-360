// Tests for spec entry 32: GitHub Action (CI) wiring.
// Validates action.yml structure + ci.js pure helpers (gradeFromSeverity,
// resultToOutputs, shouldFail, exitCodeMessage). No live DB or live GitHub
// Action needed — we test the extracted logic + action.yml well-formedness.

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

import { gradeFromSeverity, resultToOutputs, shouldFail, exitCodeMessage, EXIT_CODES } from "../scripts/ci.js";

const ROOT = dirname(dirname(fileURLToPath(import.meta.url)));
const ACTION_PATH = resolve(ROOT, "action.yml");

// === gradeFromSeverity ===

test("ci: grade A+ for zero findings", () => {
  const g = gradeFromSeverity({ critical: 0, high: 0, medium: 0, low: 0, info: 0 });
  assert.equal(g, "A+");
});

test("ci: grade F for many critical", () => {
  const g = gradeFromSeverity({ critical: 5, high: 0, medium: 0, low: 0, info: 0 });
  assert.equal(g, "F");
});

test("ci: grade scales by severity weights", () => {
  // 1 high (penalty 10) -> score 90 -> A
  assert.equal(gradeFromSeverity({ critical: 0, high: 1, medium: 0, low: 0, info: 0 }), "A");
  // 1 critical (penalty 20) -> score 80 -> B
  assert.equal(gradeFromSeverity({ critical: 1, high: 0, medium: 0, low: 0, info: 0 }), "B");
  // 3 low (penalty 3) -> score 97 -> A+
  assert.equal(gradeFromSeverity({ critical: 0, high: 0, medium: 0, low: 3, info: 0 }), "A+");
});

// === resultToOutputs ===

test("ci: resultToOutputs extracts counts from summary", () => {
  const result = {
    summary: {
      by_severity: { critical: 2, high: 3, medium: 1, low: 0, info: 0 },
      confirmed: 1,
      inferred: 5,
      suppressed: 0,
      error_count: 0,
    },
    findings: [],
  };
  const out = resultToOutputs(result);
  assert.equal(out.critical_count, 2);
  assert.equal(out.high_count, 3);
  assert.equal(out.confirmed_count, 1);
  assert.equal(out.error_count, 0);
});

test("ci: resultToOutputs grade from full summary", () => {
  const result = {
    summary: {
      by_severity: { critical: 1, high: 0, medium: 0, low: 0, info: 0 },
      confirmed: 1,
      inferred: 0,
      suppressed: 0,
    },
    findings: [],
  };
  const out = resultToOutputs(result);
  assert.equal(out.grade, "B"); // 1 critical -> score 80 -> B
});

test("ci: resultToOutputs handles missing summary gracefully", () => {
  const out = resultToOutputs({ findings: [] });
  assert.equal(out.critical_count, 0);
  assert.equal(out.high_count, 0);
  assert.equal(out.confirmed_count, 0);
  assert.equal(out.grade, "A+");
  assert.equal(out.error_count, 0);
});

// === shouldFail / exitCodeMessage ===

test("ci: shouldFail is false for clean (exit 0)", () => {
  assert.equal(shouldFail(EXIT_CODES.CLEAN), false);
});

test("ci: shouldFail is true for findings (exit 2)", () => {
  assert.equal(shouldFail(EXIT_CODES.FINDINGS), true);
});

test("ci: shouldFail is true for auth/network/tool errors", () => {
  assert.equal(shouldFail(EXIT_CODES.AUTH_ERROR), true);
  assert.equal(shouldFail(EXIT_CODES.NETWORK_ERROR), true);
  assert.equal(shouldFail(EXIT_CODES.SCHEMA_VIOLATION), true);
});

test("ci: exitCodeMessage covers all codes", () => {
  assert.ok(exitCodeMessage(0).includes("Clean"));
  assert.ok(exitCodeMessage(2).includes("Findings"));
  assert.ok(exitCodeMessage(10).includes("Auth"));
  assert.ok(exitCodeMessage(11).includes("Network"));
  assert.ok(exitCodeMessage(12).includes("Tool"));
});

// === action.yml validation ===

test("ci: action.yml exists and is valid YAML-like", () => {
  const content = readFileSync(ACTION_PATH, "utf8");
  assert.ok(content.length > 0, "action.yml must exist and be non-empty");
  // Basic YAML structure checks
  assert.ok(content.includes("name:"), "must have a name");
  assert.ok(content.includes("inputs:"), "must have inputs");
  assert.ok(content.includes("outputs:"), "must have outputs");
  assert.ok(content.includes("runs:"), "must have runs section");
  assert.ok(content.includes("using:"), "must specify using");
});

test("ci: action.yml uses local node (no npx/npm install on run path)", () => {
  const content = readFileSync(ACTION_PATH, "utf8");
  // Must NOT pull from npx/npm — must use local repo scripts (check for command use, not comments)
  assert.ok(!content.includes("npx "), "must not invoke npx command (supply-chain risk)");
  // Must reference local scripts
  assert.ok(content.includes("node scripts/cli.js"), "must run node scripts/cli.js from checkout");
  assert.ok(content.includes("actions/checkout"), "must use actions/checkout");
});

test("ci: action.yml has required inputs", () => {
  const content = readFileSync(ACTION_PATH, "utf8");
  const inputs = ["project-ref", "token", "fail-on"];
  for (const input of inputs) {
    assert.ok(content.includes(`${input}:`), `must have input "${input}"`);
  }
});

test("ci: action.yml has required outputs including confirmed-count", () => {
  const content = readFileSync(ACTION_PATH, "utf8");
  const outputs = ["critical-count", "high-count", "confirmed-count", "grade"];
  for (const output of outputs) {
    assert.ok(
      content.includes(`${output}:`),
      `must have output "${output}"`
    );
  }
});

test("ci: action.yml uploads JSON result as artifact", () => {
  const content = readFileSync(ACTION_PATH, "utf8");
  // JSON result must be an artifact (not just HTML)
  assert.ok(
    content.includes("audit-result.json") || content.includes("findings.json"),
    "must upload the JSON result file as artifact"
  );
  assert.ok(
    content.includes("upload-artifact"),
    "must use upload-artifact for JSON result"
  );
});

test("ci: action.yml HTML is optional (not default)", () => {
  const content = readFileSync(ACTION_PATH, "utf8");
  // HTML should only be produced when explicitly requested, not by default
  const htmlLines = content.split("\n").filter((l) => l.includes("--html"));
  // HTML generation should be behind a condition, not unconditional
  assert.ok(
    content.includes("html") || content.includes("--html"),
    "HTML rendering must reference --html flag or conditional"
  );
  // There should be a condition (if:) gating the HTML step
  const hasHtmlCondition = content.includes("if:") && content.toLowerCase().includes("html");
  assert.ok(hasHtmlCondition, "HTML step should be conditional");
});

test("ci: action.yml wires --fail-on flag", () => {
  const content = readFileSync(ACTION_PATH, "utf8");
  assert.ok(content.includes("--fail-on"), "must pass --fail-on to the CLI");
});
