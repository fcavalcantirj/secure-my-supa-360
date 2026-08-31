// Baseline + diff mode for spec entry 28.
//
// `--baseline <path>`:
//   - First run (file missing): writes a signed baseline of accepted findings → exit 0
//   - Subsequent runs (file exists): diffs current findings against baseline,
//     marks NEW findings as regressions, exits non-zero (2) when a new finding
//     at/above --fail-on appears vs baseline.
//
// Pure functions — no I/O apart from loadBaseline / saveBaseline (fs).
// The signature is a SHA-256 over a deterministic serialization of the payload,
// making the baseline file tamper-evident.

import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { createHash } from "node:crypto";
import { SEVERITY_RANK, EXIT_CODES, computeExitCode } from "./contract.js";

// --- Baseline creation ---

/**
 * Create a signed baseline from an audit result.
 * Extracts non-suppressed finding IDs + metadata and computes a signature.
 *
 * @param {object} result — full audit result (as produced by assembleResult / audit())
 * @returns {{ schema_version: string, project_ref: string, mode: string, generated_at: string, findings: object, signature: string }}
 */
export function createBaseline(result) {
  const findings = {};
  for (const f of result.findings || []) {
    if (!f.suppressed) {
      findings[f.id] = {
        check: f.check,
        target: f.target,
        severity: f.severity,
        confidence: f.confidence,
      };
    }
  }

  const payload = {
    schema_version: "1.0",
    project_ref: result.project_ref,
    mode: result.mode,
    generated_at: result.generated_at,
    findings,
  };

  const signature = signBaseline(payload);
  return { ...payload, signature };
}

/**
 * Compute a deterministic SHA-256 signature over the baseline payload.
 * Keys are sorted so the signature is stable regardless of insertion order.
 */
export function signBaseline(payload) {
  const sorted = {};
  for (const k of Object.keys(payload).sort()) {
    if (k === "findings" && typeof payload[k] === "object" && payload[k] !== null) {
      sorted[k] = {};
      for (const id of Object.keys(payload[k]).sort()) {
        sorted[k][id] = payload[k][id];
      }
    } else {
      sorted[k] = payload[k];
    }
  }
  const content = JSON.stringify(sorted);
  return createHash("sha256").update(content).digest("hex");
}

/**
 * Verify that a baseline's signature matches its payload.
 * Returns true if valid, false if tampered.
 */
export function verifyBaseline(baseline) {
  if (!baseline || !("signature" in baseline)) return false;
  const { signature, ...payload } = baseline;
  return signature === signBaseline(payload);
}

// --- Baseline file I/O ---

/**
 * Load + verify a baseline file from disk.
 * Throws if the file cannot be read, parsed, or fails signature verification.
 *
 * @param {string} path
 * @returns {object} the verified baseline object
 */
export function loadBaseline(path) {
  const raw = readFileSync(path, "utf8");
  const baseline = JSON.parse(raw);
  if (!verifyBaseline(baseline)) {
    throw new Error(`baseline signature mismatch for ${path} — file may be tampered`);
  }
  return baseline;
}

/**
 * Check whether a baseline file exists at the given path.
 */
export function baselineExists(path) {
  return existsSync(path);
}

/**
 * Create a baseline from an audit result and write it to disk.
 * @param {string} path
 * @param {object} result
 * @returns {object} the baseline that was written
 */
export function saveBaseline(path, result) {
  const baseline = createBaseline(result);
  writeFileSync(path, JSON.stringify(baseline, null, 2), "utf8");
  return baseline;
}

// --- Diff ---

/**
 * Diff a current audit result against a loaded baseline.
 *
 * A finding is "new" (a regression) if it appears in the current result but
 * not in the baseline (by finding ID). Suppressed findings are excluded from
 * the diff — they are allowlisted, not regressions.
 *
 * @param {object} baseline — baseline object (from loadBaseline / createBaseline)
 * @param {object} result — current audit result
 * @returns {{ newFindings: Array, existingFindings: Array, removedFindings: Array }}
 */
export function diffBaseline(baseline, result) {
  const baselineIds = new Set(Object.keys(baseline.findings || {}));

  const newFindings = [];
  const existingFindings = [];
  const removedFindings = [];
  const currentIds = new Set();

  for (const f of result.findings || []) {
    if (f.suppressed) continue;
    currentIds.add(f.id);
    if (baselineIds.has(f.id)) {
      existingFindings.push(f);
    } else {
      newFindings.push(f);
    }
  }

  for (const id of baselineIds) {
    if (!currentIds.has(id)) {
      removedFindings.push(baseline.findings[id]);
    }
  }

  return { newFindings, existingFindings, removedFindings };
}

/**
 * Build a baseline_diff summary object for inclusion in the audit result.
 *
 * @param {object} baseline
 * @param {Array} newFindings
 * @param {Array} existingFindings
 * @param {Array} removedFindings
 * @returns {object}
 */
export function buildBaselineDiff(baseline, newFindings, existingFindings, removedFindings) {
  const by_severity = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of newFindings) {
    if (f.severity in by_severity) by_severity[f.severity]++;
  }
  return {
    baseline_at: baseline.generated_at,
    new: newFindings.length,
    existing: existingFindings.length,
    removed: removedFindings.length,
    regressions_by_severity: by_severity,
    regression: newFindings.length > 0,
  };
}

// --- Exit code with baseline diff ---

/**
 * Compute the exit code when baseline diff mode is active.
 *
 * In baseline mode, the fail-gate is based on NEW findings (regressions) only —
 * known findings from the baseline do not re-trigger the gate. Honors
 * confirmedOnly: when true, only new confirmed findings count as regressions.
 *
 * @param {object} opts
 * @param {object} opts.errors
 * @param {object} opts.result — current audit result
 * @param {object} opts.baseline — loaded baseline
 * @param {string} [opts.failOn]
 * @param {boolean} [opts.confirmedOnly]
 * @returns {number} exit code
 */
export function computeBaselineExitCode({ errors, result, baseline, failOn = "high", confirmedOnly = false }) {
  if (errors.auth_error) return EXIT_CODES.AUTH_ERROR;
  if (errors.network_error) return EXIT_CODES.NETWORK_ERROR;
  if (errors.schema_violation) return EXIT_CODES.SCHEMA_VIOLATION;

  // WO-3: An incomplete scan is ALWAYS a failure, regardless of --fail-on.
  if (result.scan_complete === false) return EXIT_CODES.FINDINGS;

  if (failOn === "never") return EXIT_CODES.CLEAN;

  if (!baseline) {
    // No baseline loaded — fall back to standard fail-gate
    return computeExitCode({ errors, result, failOn, confirmedOnly });
  }

  const { newFindings } = diffBaseline(baseline, result);
  const failRank = SEVERITY_RANK[failOn] ?? SEVERITY_RANK.high;

  const hasRegression = newFindings.some(
    (f) =>
      !f.suppressed
      && (SEVERITY_RANK[f.severity] ?? 99) <= failRank
      && (!confirmedOnly || f.confidence === "confirmed")
  );

  return hasRegression ? EXIT_CODES.FINDINGS : EXIT_CODES.CLEAN;
}
