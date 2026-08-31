// CI helper — pure functions for GitHub Action output extraction.
// Spec entry 32: action.yml uses the local CLI (node scripts/cli.js),
// --fail-on flag, exit-code contract, and JSON result as artifact.
// This module is consumed by the action.yml run-step via `node -e`
// to extract counts/grade from the JSON result, and by test/ci.test.js.

import { SEVERITY_RANK, EXIT_CODES } from "./contract.js";

/**
 * Compute a letter grade from a finding summary (mirrors report.js scoring).
 * @param {object} bySeverity — { critical, high, medium, low, info }
 * @returns {string} "A+".."F"
 */
export function gradeFromSeverity(bySeverity) {
  const s = (n) => (bySeverity[n] || 0);
  const score = Math.max(
    0,
    100 - (s("critical") * 20 + s("high") * 10 + s("medium") * 4 + s("low") * 1 + s("info") * 1)
  );
  return score >= 95 ? "A+" :
    score >= 85 ? "A" :
    score >= 70 ? "B" :
    score >= 50 ? "C" :
    score >= 30 ? "D" : "F";
}

/**
 * Extract GitHub Action output values from a JSON audit result.
 * @param {object} result — the JSON result from audit.js
 * @returns {object} { critical_count, high_count, confirmed_count, grade, error_count }
 */
export function resultToOutputs(result) {
  const s = result.summary || {};
  const sev = s.by_severity || {};
  return {
    critical_count: sev.critical || 0,
    high_count: sev.high || 0,
    confirmed_count: s.confirmed || 0,
    grade: gradeFromSeverity(sev),
    error_count: s.error_count || 0,
  };
}

/**
 * Determine whether an exit code should fail a CI step.
 * Exit 2 (findings) fails; 10/11/12 (errors) also fail; 0 passes.
 */
export function shouldFail(exitCode) {
  return exitCode !== 0;
}

/**
 * Human-readable message for a non-zero exit code.
 */
export function exitCodeMessage(exitCode) {
  switch (exitCode) {
    case 0: return "Clean — no findings at/above --fail-on severity";
    case 2: return "Findings at/above --fail-on severity (see result JSON for details)";
    case 10: return "Auth error — check SUPABASE_ACCESS_TOKEN";
    case 11: return "Network error — DNS/connection failure";
    case 12: return "Tool error — output failed schema validation or secret-leak scan";
    default: return `Unexpected exit code ${exitCode}`;
  }
}

/**
 * Severity rank for fail-on comparison (re-exported for tests).
 */
export { SEVERITY_RANK, EXIT_CODES };
