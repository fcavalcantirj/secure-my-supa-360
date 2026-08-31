// Suppression / allowlist layer for spec entry 29.
//
// Reads an optional .supa360.json in the project root and applies suppression
// allowlist entries to audit findings. Suppressed findings STILL appear in the
// output (auditable) with suppressed=true and suppressed_reason, but are excluded
// from fail-gate counts (computeExitCode skips them).
//
// .supa360.json format:
// {
//   "suppressions": [
//     { "target": "bucket:content-media", "check": "storage_bucket_public", "reason": "..." },
//     { "target": "table:public_blog_posts", "reason": "..." },
//     ...
//   ]
// }
//
// A suppression WITHOUT a "check" field suppresses ALL findings for that target.
// A suppression WITH a "check" field suppresses only that specific check on that target.

import { readFileSync } from "node:fs";

const SUPPRESSION_FILE = ".supa360.json";

/**
 * Load suppression allowlist entries from .supa360.json in the given directory.
 * Returns an array of { target, check?, reason } (empty array if file missing/invalid).
 *
 * @param {string} dir — project root to look for .supa360.json (default: cwd)
 * @returns {Array<{target: string, check?: string, reason?: string}>}
 */
export function loadSuppressions(dir) {
  const cwd = dir || process.cwd();
  let raw;
  try {
    raw = readFileSync(`${cwd}/${SUPPRESSION_FILE}`, "utf8");
  } catch {
    return [];
  }
  try {
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed.suppressions) ? parsed.suppressions : [];
  } catch {
    return [];
  }
}

/**
 * Apply suppressions to a list of findings. Returns a NEW array (no mutation).
 * A finding is suppressed if its target matches a suppression entry (and, if the
 * entry has a "check", the finding's check also matches).
 *
 * @param {Array} findings — raw or normalized findings
 * @param {Array<{target: string, check?: string, reason?: string}>} suppressions
 * @returns {Array} findings with suppressed/suppressed_reason set on matching items
 */
export function applySuppressions(findings, suppressions) {
  if (!suppressions || suppressions.length === 0) return findings;

  // Index suppressions by target for O(n) lookup.
  // Each target may have multiple entries (different checks).
  const byTarget = new Map();
  for (const s of suppressions) {
    const key = s.target;
    if (!byTarget.has(key)) byTarget.set(key, []);
    byTarget.get(key).push(s);
  }

  return findings.map((f) => {
    const matches = byTarget.get(f.target);
    if (!matches) return f;

    // Find the best match: exact check match first, then any check-less entry.
    const specific = matches.find((s) => s.check && s.check === f.check);
    const generic = matches.find((s) => !s.check);
    const match = specific || generic;

    if (!match) return f;

    return {
      ...f,
      suppressed: true,
      suppressed_reason: match.reason || null,
    };
  });
}

/**
 * Detect stale suppressions — allowlisted targets that no longer produce any
 * finding. Returns the stale entries so they can be warned about.
 *
 * @param {Array} findings — the full findings list (after suppression)
 * @param {Array<{target: string, check?: string}>} suppressions
 * @returns {Array<{target: string, check?: string, reason?: string}>} stale entries
 */
export function checkStaleSuppressions(findings, suppressions) {
  if (!suppressions || suppressions.length === 0) return [];

  const findingTargets = new Set(findings.map((f) => f.target));
  return suppressions.filter((s) => !findingTargets.has(s.target));
}

/**
 * Compute suppressed-only summary counts (for the result object).
 * @param {Array} findings — normalized findings (after suppression applied)
 * @returns {{ suppressed: number, suppressed_by_check: Object<string, number> }}
 */
export function suppressionSummary(findings) {
  const suppressed = findings.filter((f) => f.suppressed);
  const byCheck = {};
  for (const f of suppressed) {
    byCheck[f.check] = (byCheck[f.check] || 0) + 1;
  }
  return { suppressed: suppressed.length, suppressed_by_check: byCheck };
}
