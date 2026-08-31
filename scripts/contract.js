// Contract layer: normalizes raw findings into the stable JSON contract v1.0,
// builds the summary, enforces deterministic ordering, scans for secret leaks,
// and computes exit codes. Pure — no I/O, no fetch. (scripts/checks/rls.js etc.
// produce detection findings; this layer shapes them for the agent contract.)
//
// Spec entry 0 (JSON contract) + entry 1 (exit codes) foundation.

import { createHash } from "node:crypto";

// --- Stable IDs ---

/** Deterministic finding ID: first 12 hex chars of sha1(check:target). */
export function findingId(check, target) {
  return createHash("sha1").update(`${check}:${target}`).digest("hex").slice(0, 12);
}

// --- Severity ranking ---

export const SEVERITY_RANK = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

// --- Exit codes (spec entry 1) ---

export const EXIT_CODES = {
  CLEAN: 0,          // no findings at/above --fail-on
  FINDINGS: 2,       // findings at/above --fail-on exist
  AUTH_ERROR: 10,    // token rejected / 401 / 403
  NETWORK_ERROR: 11, // DNS / connection refused / fetch rejection
  SCHEMA_VIOLATION: 12, // tool's own output failed schema validation
};

// --- Probe normalization ---

/**
 * Extract + normalize a probe object to the contract shape
 * { status, bytes, sample: { row_count, columns } } or null.
 * Handles the different probe shapes produced by check modules:
 *   rls.js      → evidence.probe = { status, row_count, bytes }
 *   rpc.js      → evidence.probe = { status, reason }
 *   views.js    → evidence.probe = { status, row_count, bytes }
 *   audit.js inline → probe = { confirmed, status, sample, reason }
 */
export function normalizeProbe(finding) {
  // Top-level probe (audit.js inline findings, e.g. realtime)
  let p = finding.probe;
  // evidence.probe (check-module findings)
  if (!p && finding.evidence?.probe) p = finding.evidence.probe;

  if (!p || typeof p !== "object") return null;

  const row_count = p.row_count ?? p.sample?.row_count ?? null;
  const columns = p.columns ?? p.sample?.columns ?? null;
  const bytes = p.bytes ?? p.sample?.bytes_returned ?? null;

  return {
    status: p.status != null ? p.status : null,
    bytes: bytes != null ? bytes : null,
    sample: {
      row_count: row_count != null ? row_count : null,
      columns: Array.isArray(columns) ? columns.slice(0, 8) : null,
    },
  };
}

// --- Finding normalization ---

const BASE_FIX = {
  sql: [],
  rollback_sql: [],
  rollback_management_api_action: null,
  dashboard_action: null,
  management_api_action: null,
  requires_service_role: false,
};

/**
 * Normalize a single raw finding (from any check module or audit.js inline
 * code) into the full contract v1.0 shape.
 *
 * Ensures: id, fix.{sql,rollback_sql,dashboard_action,management_api_action,
 * requires_service_role}, references[], suppressed, suppressed_reason.
 * Keeps backward-compat fields (title, explain, fix_sql, details) for report.js.
 */
export function normalizeFinding(raw) {
  const fix = { ...BASE_FIX, ...(raw.fix || {}) };
  // Handle legacy flat fix_sql string (audit.js inline findings): backfill fix.sql[]
  if (!fix.sql.length && raw.fix_sql) {
    fix.sql = [raw.fix_sql];
  }
  const probe = normalizeProbe(raw);

  const normalized = {
    id: raw.id || findingId(raw.check, raw.target || "unknown"),
    check: raw.check,
    category: raw.category || "uncategorized",
    severity: raw.severity || "info",
    confidence: raw.confidence || "inferred",
    target: raw.target || "unknown",
    // Check modules are inconsistent: some build `evidence`, some build `details`
    // (function-body.js uses `details` exclusively). Reading only `evidence` silently
    // dropped both — 55 findings shipped `evidence: {}`, including every
    // function_secdef_missing_auth_check, whose auth_check grade and body_preview are
    // the only way a human can adjudicate the most severe check in the tool.
    evidence: raw.evidence || raw.details || {},
    fix: {
      sql: Array.isArray(fix.sql) ? fix.sql : (fix.sql ? [String(fix.sql)] : []),
      rollback_sql: Array.isArray(fix.rollback_sql) ? fix.rollback_sql : (fix.rollback_sql ? [String(fix.rollback_sql)] : []),
      dashboard_action: fix.dashboard_action || null,
      management_api_action: fix.management_api_action || null,
      rollback_management_api_action: fix.rollback_management_api_action || null,
      requires_service_role: !!fix.requires_service_role,
    },
    references: Array.isArray(raw.references) ? raw.references : [],
    suppressed: !!raw.suppressed,
    suppressed_reason: raw.suppressed_reason || null,
  };

  // Top-level probe (null when not probed)
  normalized.probe = probe;

  // Backward-compatible fields for report.js / existing consumers
  if (raw.title) normalized.title = raw.title;
  if (raw.explain) normalized.explain = raw.explain;
  if (raw.details) normalized.details = raw.details;
  if (raw.exploitable_without_auth !== undefined)
    normalized.exploitable_without_auth = raw.exploitable_without_auth;

  // Legacy flat fix_sql for report.js compat
  normalized.fix_sql = normalized.fix.sql.join("\n");

  return normalized;
}

// --- Deterministic sort ---

/**
 * Sort findings deterministically: severity desc (critical first),
 * then check asc, then target asc. Stable across runs.
 */
export function sortFindings(findings) {
  // WO-17: deduplicate by id — keep first occurrence, drop later dupes.
  // Collisions happen when the same id (check:target) is produced by
  // different code paths (e.g. history verb groups, column-grant duplicates).
  // Baseline keying on id would silently drop one of each pair.
  // Use findingId(check:target) as fallback when id is absent (raw test data).
  const seen = new Set();
  const deduped = findings.filter((f) => {
    const key = f.id || findingId(f.check, f.target || "unknown");
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
  return deduped.sort((a, b) => {
    const sa = SEVERITY_RANK[a.severity] ?? 99;
    const sb = SEVERITY_RANK[b.severity] ?? 99;
    if (sa !== sb) return sa - sb;
    if (a.check !== b.check) return a.check < b.check ? -1 : 1;
    return a.target < b.target ? -1 : a.target > b.target ? 1 : 0;
  });
}

// --- Summary builder ---

export function buildSummary(findings) {
  const by_severity = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  const confirmed_by_severity = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  const inferred_by_severity = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  let confirmed = 0;
  let inferred = 0;
  let suppressed = 0;

  for (const f of findings) {
    if (f.severity in by_severity) by_severity[f.severity]++;
    if (f.confidence === "confirmed") {
      confirmed++;
      if (f.severity in confirmed_by_severity) confirmed_by_severity[f.severity]++;
    } else {
      inferred++;
      if (f.severity in inferred_by_severity) inferred_by_severity[f.severity]++;
    }
    if (f.suppressed) suppressed++;
  }

  return { by_severity, confirmed, inferred, confirmed_by_severity, inferred_by_severity, suppressed };
}

// --- Secret scanner ---

// Patterns that should NEVER appear in JSON output. These match actual secret
// VALUES, not keywords like "service_role" used in SQL examples.
const SECRET_PATTERNS = [
  {
    name: "supabase_pat",
    regex: /sbp_[a-zA-Z0-9_]{20,}/g,
    desc: "Supabase Personal Access Token (sbp_…)",
  },
  {
    name: "jwt_token",
    // Full 3-part JWT: header.payload.signature (each part ≥ 10 base64 chars)
    regex: /eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}/g,
    desc: "JWT token (service_role, anon, or access token)",
  },
  {
    name: "db_connstring",
    regex: /postgres(?:ql)?:\/\/[^:\s]+:[^@\s]+@/g,
    desc: "PostgreSQL connection string with embedded password",
  },
  {
    name: "supabase_secret",
    regex: /supabase_secret_[a-zA-Z0-9_]{20,}/g,
    desc: "Supabase secret value",
  },
];

/** Scan a JSON string for secrets. Returns array of {name, match}. */
export function scanForSecrets(jsonStr) {
  const found = [];
  for (const { name, regex, desc } of SECRET_PATTERNS) {
    let m;
    const re = new RegExp(regex.source, regex.flags);
    while ((m = re.exec(jsonStr)) !== null) {
      found.push({ name, match: m[0].slice(0, 8) + "…", desc });
    }
  }
  return found;
}

// --- Exit code computation ---

/**
 * Compute the process exit code for a completed audit result.
 *
 * Priority: auth_error → network_error → schema_violation → findings → clean.
 *
 * @param {object} opts
 * @param {object} opts.errors  - { auth_error?, network_error?, schema_violation?, validation_errors? }
 * @param {object} opts.result  - the validated result object
 * @param {string} opts.failOn  - severity threshold: 'critical'|'high'|'medium'|'low'|'info'
 * @param {boolean} [opts.confirmedOnly] - when true, only confidence==='confirmed'
 *   findings count toward the fail-on gate (entry 35: inferred-only RPC grants
 *   don't trigger CI failure). Default: false (both confirmed and inferred count).
 * @returns {number} exit code (0, 2, 10, 11, or 12)
 */
export function computeExitCode({ errors, result, failOn = "high", confirmedOnly = false }) {
  if (errors.auth_error) return EXIT_CODES.AUTH_ERROR;
  if (errors.network_error) return EXIT_CODES.NETWORK_ERROR;
  if (errors.schema_violation) return EXIT_CODES.SCHEMA_VIOLATION;

  // WO-3: An incomplete scan (any check section errored) is ALWAYS a failure,
  // regardless of --fail-on. A tool that fails to enumerate and then looks clean
  // is the worst failure mode — never let "we could not look" be mistaken for
  // "we looked and it is fine."
  if (result.scan_complete === false) return EXIT_CODES.FINDINGS;

  if (failOn === "never") return EXIT_CODES.CLEAN;

  const failRank = SEVERITY_RANK[failOn] ?? SEVERITY_RANK.high;
  const hasFindings = (result.findings || []).some(
    (f) => !f.suppressed
      && (SEVERITY_RANK[f.severity] ?? 99) <= failRank
      && (!confirmedOnly || f.confidence === "confirmed")
  );
  return hasFindings ? EXIT_CODES.FINDINGS : EXIT_CODES.CLEAN;
}

// --- Full result assembly ---

/**
 * Assemble a complete contract v1.0 result from raw findings + metadata.
 * Normalizes, sorts, builds summary, and returns the full result object.
 *
 * @param {object} opts
 * @param {string} opts.project_ref
 * @param {string} [opts.project_name]
 * @param {string} [opts.region]
 * @param {string} opts.mode — 'audit-active' | 'audit-passive' | 'discover'
 * @param {Array} opts.rawFindings — findings from check modules + audit.js inline
 * @param {Array} [opts.errors] — per-check error entries from fault isolation
 */
export function assembleResult({ project_ref, project_name, region, mode, rawFindings, errors = [], generated_at = null }) {
  const findings = sortFindings(rawFindings.map(normalizeFinding));
  const summary = buildSummary(findings);

  return {
    schema_version: "1.0",
    project_ref,
    project_name: project_name || null,
    region: region || null,
    generated_at: generated_at || new Date().toISOString(),
    mode,
    summary,
    findings,
    errors,
    n_tables_scanned: rawFindings.length, // approximate; audit.js overrides with real count
  };
}

// --- Auth/network error classification ---

/** Given an error from the Supabase API or fetch, classify it. */
export function classifyError(e) {
  const msg = String(e?.message || e);
  // Supabase Management API returns 401/403 for invalid tokens
  if (/\b401\b/.test(msg) || /\b403\b/.test(msg) || /unauthorized/i.test(msg) || /forbidden/i.test(msg)) {
    return "auth_error";
  }
  // Network-level failures
  if (/network/i.test(msg) || /ENOTFOUND/i.test(msg) || /ECONNREFUSED/i.test(msg) || /ECONNRESET/i.test(msg) || /ETIMEDOUT/i.test(msg)) {
    return "network_error";
  }
  return "other";
}
