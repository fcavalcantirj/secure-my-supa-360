#!/usr/bin/env node
// scripts/remediate.js — Remediates findings from a prior JSON audit result.
//
// DRY-RUN by default: prints the ordered plan (SQL + management-API + dashboard
// actions) and does nothing. With --apply, executes SQL fixes inside
// BEGIN/COMMIT per finding (via Management API database/query endpoint) and
// management-API PATCH actions (via PAT). Dashboard-only actions are listed
// with their exact click-path but never executed.
//
// Usage:
//   node scripts/remediate.js <result.json> [--apply] [--token <tok>]
//   cat result.json | node scripts/remediate.js [--apply] [--token <tok>]
//   node scripts/cli.js remediate <result.json> [--apply] [--token <tok>]
//
// Exit codes: 0=clean/applied, 2=some failures, 10=auth, 11=network,
//             12=input/validation failure.
// Spec entry 23 (remediation — build the missing file package.json references).

import { readFileSync, writeFileSync } from "node:fs";
import { createInterface } from "node:readline";
import { createHash } from "node:crypto";
import { EXIT_CODES, SEVERITY_RANK, scanForSecrets, classifyError } from "./contract.js";
import { applyRefConfig } from "./refconfig.js";
import { captureState, generateRollbackFromState } from "./checks/state.js";

const API = "https://api.supabase.com/v1";
const MGMT_BASE = "https://api.supabase.com";
const UA = "supabase-security/0.4-remediate";

// Two-tier blocklist that gates remediate --apply / --rollback (and the lab write-path).
// Ref membership is compared as a SHA-256 hash so this public repo never names real
// client projects — a hashed ref cannot be reverse-engineered to obtain the original.
//
//   Tier 1 (PERMANENT_BLOCKED_REF_HASHES) — one-way door: NEVER unblockable.
//     Checked FIRST, before any lab override. No env var + flag combination can
//     unblock these. A different SUPA360_LAB_REF never unblocks a permanent ref.
//   Tier 2 (LAB_ELIGIBLE_REF_HASHES + SUPA360_BLOCKED_REFS env) — blocked by
//     default, unblockable via full ceremony: env SUPA360_LAB_REF=<ref> AND
//     --i-understand-this-is-destructive, where SUPA360_LAB_REF must match the
//     target ref exactly.
//
// Both SHIPPED sets are EMPTY on purpose: this package must not encode any specific
// project's identity (previously the maintainer's own prod+lab refs were hardcoded
// here, which produced a false "production refs are hard-blocked" promise for every
// other user). Correctness never depends on shipped hashes — each tier has an env
// source, read at call time:
//   SUPA360_PERMANENT_BLOCKED_REFS -> tier 1, NEVER unblockable. Put production here.
//   SUPA360_BLOCKED_REFS           -> tier 2, unblockable via full lab ceremony.
// These are NOT interchangeable: a ref listed only in SUPA360_BLOCKED_REFS can be
// unblocked by SUPA360_LAB_REF naming that same ref. Production belongs in tier 1.
// The two-tier *logic* is proven by test/lab.test.js with injected dummy sets, and
// the env-sourced tiers by the ceremony matrix in the same file.
const refHash = (r) => createHash("sha256").update(String(r).trim().toLowerCase()).digest("hex");

/** Parse a comma-separated ref list from an env var. */
const envRefList = (name) => (process.env[name] || "").split(",").map((s) => s.trim()).filter(Boolean);

/** True when env var `name` names `ref` (compared as hashes, never as plaintext). */
export const envNamesRef = (name, ref) => envRefList(name).some((r) => refHash(r) === refHash(ref));

const PERMANENT_BLOCKED_REF_HASHES = new Set();   // load-bearing logic; injected in tests, never seeded with a real ref
const LAB_ELIGIBLE_REF_HASHES = new Set();        // load-bearing logic; injected in tests, never seeded with a real ref

// Backward-compat alias: the union of both sets (everything that's blocked).
const BLOCKED_REF_HASHES = new Set([...PERMANENT_BLOCKED_REF_HASHES, ...LAB_ELIGIBLE_REF_HASHES]);

/**
 * Check if a ref is blocked from remediation.
 *
 * Two-tier logic:
 *  1. PERMANENT_BLOCKED_REF_HASHES — ALWAYS blocked. Checked before any lab
 *     override. Even with SUPA360_LAB_REF=<same ref> + --i-understand-this-is-destructive,
 *     a permanent ref stays blocked. A different lab ref does NOT unblock it.
 *  2. LAB_ELIGIBLE_REF_HASHES + SUPA360_BLOCKED_REFS — blocked by default but
 *     unblocked when ALL of: opts.allowLab=true, opts.destructiveAck=true,
 *     and env SUPA360_LAB_REF matches this exact ref (hash comparison).
 *
 * @param {string} ref — project ref
 * @param {object} opts — { allowLab?, destructiveAck? }
 * @param {Set} _permSet — injectable for testing (defaults to PERMANENT_BLOCKED_REF_HASHES)
 * @param {Set} _labSet — injectable for testing (defaults to LAB_ELIGIBLE_REF_HASHES)
 * @returns {boolean} true if blocked
 */
export function isBlockedRef(ref, opts = {}, _permSet, _labSet) {
  const permSet = _permSet || PERMANENT_BLOCKED_REF_HASHES;
  const labSet = _labSet || LAB_ELIGIBLE_REF_HASHES;

  // Tier 1: permanent block — ALWAYS blocked, checked BEFORE any override.
  // Sourced from the injected/shipped set AND from SUPA360_PERMANENT_BLOCKED_REFS,
  // so an operator can protect their OWN production without shipping a hash.
  // Nothing below can unblock a tier-1 ref — including SUPA360_LAB_REF naming it.
  if (permSet.has(refHash(ref)) || envNamesRef("SUPA360_PERMANENT_BLOCKED_REFS", ref)) return true;

  // Tier 2: lab-eligible blocklist (hard-coded + operator env)
  let blocked = labSet.has(refHash(ref)) || envNamesRef("SUPA360_BLOCKED_REFS", ref);
  if (!blocked) return false;

  // Tier 3: lab override — only unblocks lab-eligible refs (never permanent)
  if (!opts.allowLab || !opts.destructiveAck) return true;
  const labRef = process.env.SUPA360_LAB_REF;
  if (!labRef) return true;
  if (refHash(labRef) !== refHash(ref)) return true;
  return false;
}


/** Interactive y/N confirmation (TTY only). Returns true on 'yes'. */
function promptConfirm(message) {
  const rl = createInterface({ input: process.stdin, output: process.stdout });
  return new Promise((resolve) => {
    rl.question(message, (answer) => {
      rl.close();
      resolve(answer.trim().toLowerCase());
    });
  });
}

/** Default snapshot writer: writes JSON to disk under fixtures/. */
function defaultWriteSnapshot(path, content) {
  try {
    writeFileSync(path, content, "utf8");
  } catch {
    // Non-fatal — snapshot is best-effort for reversibility.
  }
}

// === PURE FUNCTIONS (testable without I/O) ===

// isExecutableSql is implemented in scripts/checks/state.js and re-exported here
// for backward compatibility (lab.js, tests, and the CLI all import it from
// remediate.js). The implementation moved to state.js because both remediate()
// and the checks need the same predicate. We import it locally so it is in
// module scope (extractExecutableSql, planRemediations use it directly), and
// re-export for external consumers that import from remediate.js.
import { isExecutableSql } from "./checks/state.js";
export { isExecutableSql };

/**
 * Extract executable SQL lines from a finding's fix.sql array.
 * Filters out comment-only lines and placeholder lines.
 */
export function extractExecutableSql(fix) {
  if (!fix || !Array.isArray(fix.sql)) return [];
  return fix.sql.filter(isExecutableSql);
}

/**
 * Categorize a finding's fix into actionable types.
 * @returns {{ hasSql: boolean, hasMgmtApi: boolean, hasDashboard: boolean,
 *            isDashboardOnly: boolean, hasNoFix: boolean }}
 */
export function categorizeFix(finding) {
  const fix = finding.fix || {};
  const sqlLines = extractExecutableSql(fix);
  return {
    hasSql: sqlLines.length > 0,
    hasMgmtApi: !!fix.management_api_action,
    hasDashboard: !!fix.dashboard_action,
    isDashboardOnly: sqlLines.length === 0 && !fix.management_api_action && !!fix.dashboard_action,
    hasNoFix: sqlLines.length === 0 && !fix.management_api_action && !fix.dashboard_action,
  };
}

/**
 * Build an ordered remediation plan from a JSON result.
 * Filters suppressed findings and sorts by severity (highest first),
 * then check, then target — matching audit.js's deterministic ordering.
 *
 * @param {object} result — JSON result from audit.js (must have findings[])
 * @returns {Array} plan items, each with id, check, severity, fix, categories, etc.
 */
export function planRemediations(result) {
  const findings = (result.findings || []).filter((f) => !f.suppressed);
  const sorted = [...findings].sort((a, b) => {
    const sa = SEVERITY_RANK[a.severity] ?? 99;
    const sb = SEVERITY_RANK[b.severity] ?? 99;
    if (sa !== sb) return sa - sb;
    if (a.check !== b.check) return a.check < b.check ? -1 : 1;
    return a.target < b.target ? -1 : a.target > b.target ? 1 : 0;
  });

  return sorted.map((f) => {
    const cats = categorizeFix(f);
    return {
      id: f.id,
      check: f.check,
      category: f.category,
      severity: f.severity,
      confidence: f.confidence,
      target: f.target,
      title: f.title || f.check,
      explain: f.explain || "",
      fix: f.fix,
      rollback_sql: Array.isArray(f.fix?.rollback_sql) ? f.fix.rollback_sql : [],
      requires_service_role: !!f.fix?.requires_service_role,
      categories: cats,
      sql_to_execute: cats.hasSql ? extractExecutableSql(f.fix) : [],
      management_api_action: f.fix?.management_api_action || null,
      rollback_management_api_action: f.fix?.rollback_management_api_action || null,
      dashboard_action: f.fix?.dashboard_action || null,
    };
  });
}

// === SUMMARY BUILDERS ===

function buildDryRunSummary(plan) {
  return {
    total: plan.length,
    sql_executable: plan.filter((p) => p.categories.hasSql).length,
    mgmt_api_executable: plan.filter((p) => p.categories.hasMgmtApi).length,
    dashboard_only: plan.filter((p) => p.categories.isDashboardOnly).length,
    no_fix: plan.filter((p) => p.categories.hasNoFix).length,
  };
}

function buildApplySummary(results) {
  const applied = results.filter((r) => r.actions.some((a) => a.status === "applied")).length;
  const failed = results.filter((r) => r.actions.some((a) => a.status === "failed")).length;
  const skipped = results.filter((r) => r.actions.some((a) => a.status === "skipped")).length;
  return { total: results.length, applied, failed, skipped };
}

/**
 * Build the post-fix verification summary.
 * @param {Array} verifyItems — items from verifyRemediation
 * @returns {{ fixed_confirmed: number, fixed_unverified: number, fixed_failed: number, needs_dashboard: number }}
 */
function buildVerifySummary(verifyItems) {
  return {
    fixed_confirmed: verifyItems.filter((v) => v.remediation_verified === true).length,
    fixed_unverified: verifyItems.filter((v) => v.status === "unverified" && v.remediation_verified === null).length,
    fixed_failed: verifyItems.filter((v) => v.remediation_verified === false).length,
    needs_dashboard: verifyItems.filter((v) => v.status === "needs_dashboard" || v.needs_dashboard === true).length,
  };
}

/**
 * Verify that remediation was effective by re-running checks after apply.
 *
 * For each plan item where a fix was actually applied (SQL or management-API),
 * the `verifyFn` callback re-executes the original probe/query and reports
 * whether the finding is now closed (anonymous probe returns 42501/blocked,
 * or the config now reads hardened). Dashboard-only and not-applied findings
 * are marked accordingly without calling verifyFn.
 *
 * @param {Array} plan — from planRemediations()
 * @param {Array} results — execResults from remediate()
 * @param {function|null} [verifyFn] — async (planItem) => { verified: boolean, reason?: string }
 *        If null/omitted, applied items are marked "unverified" with a reason.
 * @returns {Promise<{ items: Array, summary: object }>}
 */
export async function verifyRemediation(plan, results, verifyFn = null) {
  const items = [];

  for (const item of plan) {
    const execResult = results.find((r) => r.id === item.id);
    const wasApplied = execResult && execResult.actions.some((a) => a.status === "applied");

    // Dashboard-only: cannot be auto-verified — remediation_verified=null (unknown, not failed).
    if (item.categories.isDashboardOnly) {
      items.push({
        id: item.id,
        check: item.check,
        target: item.target,
        status: "needs_dashboard",
        remediation_verified: null,
        needs_dashboard: true,
        reason: "Dashboard-only action — requires manual completion",
      });
      continue;
    }

    // No executable fix or not applied: nothing to verify.
    if (item.categories.hasNoFix || !wasApplied) {
      items.push({
        id: item.id,
        check: item.check,
        target: item.target,
        status: "skipped",
        remediation_verified: null,
        needs_dashboard: false,
        reason: "Fix was not applied (no executable action or was skipped)",
      });
      continue;
    }

    // Applied SQL or management-API fix: re-run the original check/probe.
    if (verifyFn) {
      try {
        const v = await verifyFn(item);
        items.push({
          id: item.id,
          check: item.check,
          target: item.target,
          status: v.verified ? "verified" : "unverified",
          remediation_verified: v.verified,
          needs_dashboard: false,
          reason: v.reason || (v.verified ? "Verification check passed" : "Verification check still fails"),
        });
      } catch (e) {
        items.push({
          id: item.id,
          check: item.check,
          target: item.target,
          status: "unverified",
          remediation_verified: false,
          needs_dashboard: false,
          reason: `Verification error: ${e.message}`,
        });
      }
    } else {
      items.push({
        id: item.id,
        check: item.check,
        target: item.target,
        status: "unverified",
        remediation_verified: null,
        needs_dashboard: false,
        reason: "No verification callback provided",
      });
    }
  }

  return {
    items,
    summary: buildVerifySummary(items),
  };
}

// === TRANSPORT (injectable for tests) ===

/** Execute SQL via the Supabase Management API database/query endpoint.
 *  @param {string} token — PAT
 *  @param {string} ref — project ref
 *  @param {string} query — SQL to execute (can be multi-statement including BEGIN/COMMIT)
 *  @returns {Promise<any>} query result rows */
export async function dbQuery(token, ref, query) {
  const r = await fetch(`${API}/projects/${ref}/database/query`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
      "User-Agent": UA,
    },
    body: JSON.stringify({ query }),
  });
  if (!r.ok) {
    const txt = await r.text();
    if (r.status === 401 || r.status === 403) {
      const err = new Error(`Remediation SQL auth error (${r.status}): ${txt.slice(0, 300)}`);
      err.code = "AUTH_ERROR";
      throw err;
    }
    throw new Error(`Remediation SQL failed (${r.status}): ${txt.slice(0, 500)}`);
  }
  return r.json();
}

/** Execute a management API request (PATCH/POST/etc).
 *  @param {string} token — PAT
 *  @param {string} method — HTTP method
 *  @param {string} path — path starting with /v1/ (relative to api.supabase.com) or full URL
 *  @param {object} body — request body
 *  @returns {Promise<any>} parsed JSON response */
export async function mgmtRequest(token, method, path, body) {
  const url = path.startsWith("http") ? path : `${MGMT_BASE}${path}`;
  const options = {
    method,
    headers: {
      Authorization: `Bearer ${token}`,
      "User-Agent": UA,
    },
  };
  if (body !== undefined) {
    options.headers["Content-Type"] = "application/json";
    options.body = JSON.stringify(body);
  }
  const r = await fetch(url, options);
  if (!r.ok) {
    const txt = await r.text();
    if (r.status === 401 || r.status === 403) {
      const err = new Error(`Management API auth error (${r.status}): ${txt.slice(0, 300)}`);
      err.code = "AUTH_ERROR";
      throw err;
    }
    throw new Error(`Management API error (${method} ${path} -> ${r.status}): ${txt.slice(0, 500)}`);
  }
  const text = await r.text();
  if (!text) return {};
  try {
    return JSON.parse(text);
  } catch {
    return { raw: text };
  }
}

// === CORE REMEDIATION ===

/**
 * Execute remediation on a JSON audit result.
 *
 * DRY-RUN (default): returns the plan without executing any fixes.
 * APPLY (--apply): executes SQL fixes in BEGIN/COMMIT per finding via the
 *   Management API database/query endpoint, management-API PATCH actions via
 *   the PAT, and lists dashboard-only actions with their click-path.
 *
 * @param {object} result — JSON result from audit.js ({ project_ref, findings })
 * @param {object} [opts]
 * @param {boolean} [opts.dryRun=true] — in dry-run, no fixes are executed
 * @param {string} [opts.token] — PAT (required when dryRun=false)
 * @param {string} [opts.ref] — project ref (defaults to result.project_ref)
 * @param {function} [opts._dbQuery] — injectable: (query) => Promise<any>
 * @param {function} [opts._mgmtRequest] — injectable: (method, path, body) => Promise<any>
 * @param {function} [opts._writeSnapshot] — injectable: (path, content) => void
 * @param {string} [opts.service_role_key] — service_role key for findings with requires_service_role=true
 * @param {function} [opts.verifyFn] — injectable: async (planItem) => { verified, reason } for post-fix re-verification (entry 25)
 * @param {Set} [opts._permSet] — injectable permanent blocklist (for testing the un-unblockable tier)
 * @param {Set} [opts._labSet] — injectable lab-eligible blocklist (for testing)
 * @returns {Promise<object>} { project_ref, mode, plan, results?, summary }
 */
export async function remediate(result, opts = {}) {
  const {
    dryRun = true,
    token = process.env.SUPABASE_ACCESS_TOKEN,
    ref = result.project_ref,
    service_role_key = process.env.SUPABASE_SERVICE_ROLE_KEY,
    _dbQuery,
    _mgmtRequest,
    _writeSnapshot,
    verifyFn,
    allowLab = false,
    destructiveAck = false,
    _permSet,
    _labSet,
  } = opts;

  const plan = planRemediations(result);

  if (dryRun) {
    return {
      project_ref: ref,
      mode: "dry-run",
      plan,
      summary: buildDryRunSummary(plan),
    };
  }

  // Guard: hard production-ref blocklist — check BEFORE token so a blocked ref
  // is refused immediately, even without a token (safety first, always).
  if (isBlockedRef(ref, { allowLab, destructiveAck }, _permSet, _labSet)) {
    const err = new Error(`refusing: production ref — remediation is disabled for known production projects`);
    err.code = "PROD_REF_BLOCKED";
    throw err;
  }

  if (!token) {
    const err = new Error("Token required for --apply. Set SUPABASE_ACCESS_TOKEN or pass --token.");
    err.code = "AUTH_ERROR";
    throw err;
  }

  // Snapshot before applying (for reversibility — entry 26).
  // The snapshot captures the full plan so a future rollback/restore can
  // reconstruct pre-fix state. In tests, inject _writeSnapshot to control it;
  // the CLI (main()) always passes defaultWriteSnapshot so a file is always
  // written before any mutation.
  let snapshotPath = null;
  if (_writeSnapshot) {
    const snapshot = {
      project_ref: ref,
      timestamp: new Date().toISOString(),
      plan: plan.map((p) => ({
        id: p.id,
        check: p.check,
        target: p.target,
        severity: p.severity,
        requires_service_role: p.requires_service_role,
        sql_to_execute: p.sql_to_execute,
        rollback_sql: p.rollback_sql,
        rollback_sql_exact: null,
        captured_state: null,
        rollback_exact: false,
        management_api_action: p.management_api_action,
        rollback_management_api_action: p.rollback_management_api_action,
        dashboard_action: p.dashboard_action,
      })),
    };
    snapshotPath = `fixtures/remediation_snapshot_${Date.now()}.json`;
    _writeSnapshot(snapshotPath, JSON.stringify(snapshot, null, 2));
  }

  // Execute fixes in severity order (highest first).
  // Each finding's SQL is wrapped in its own BEGIN/COMMIT transaction so
  // a failure on one finding doesn't corrupt another.
  const dbFn = _dbQuery || ((query) => dbQuery(token, ref, query));
  const mgmtFn = _mgmtRequest || ((method, path, body) => mgmtRequest(token, method, path, body));

  const execResults = [];
  const stateCaptureResults = new Map();
  for (const item of plan) {
    const execItem = {
      id: item.id,
      check: item.check,
      target: item.target,
      severity: item.severity,
      actions: [],
    };

    // Dashboard-only: list click-path, never execute.
    if (item.categories.isDashboardOnly) {
      execItem.actions.push({
        type: "dashboard_skip",
        status: "skipped",
        click_path: item.dashboard_action,
      });
      execResults.push(execItem);
      continue;
    }

    // No executable fix at all.
    if (item.categories.hasNoFix) {
      execItem.actions.push({
        type: "no_fix",
        status: "skipped",
        reason: "No executable fix available for this finding type.",
      });
      execResults.push(execItem);
      continue;
    }

    // Guard: requires_service_role — skip if no service_role key is present.
    if (item.requires_service_role && !service_role_key) {
      execItem.actions.push({
        type: "no_fix",
        status: "skipped",
        reason: "requires_service_role is true but no service_role key provided — apply manually",
      });
      execResults.push(execItem);
      continue;
    }

    // Execute SQL fixes inside BEGIN/COMMIT per finding.
    // WO-5: capture the target's real ACL state *before* applying, so the
    // rollback can restore the exact prior privileges — not a hardcoded template
    // that may grant privileges the role never held.
    if (item.categories.hasSql) {
      // Capture pre-fix ACL state for exact rollback generation.
      let capturedState = null;
      let rollbackSqlExact = null;
      let rollbackExact = false;
      if (token && ref) {
        capturedState = await captureState(token, ref, item, dbFn);
        if (capturedState) {
          rollbackSqlExact = generateRollbackFromState(capturedState, item);
          rollbackExact = rollbackSqlExact && rollbackSqlExact.length > 0;
        }
      }

      // Determine whether a rollback can be derived: exact (from state) or
      // template (fallback). If neither, skip — never apply on a guess.
      const templateExec = (item.rollback_sql || []).filter(isExecutableSql);
      const canRollback = (rollbackSqlExact && rollbackExact) || templateExec.length > 0;

      if (!canRollback) {
        execItem.actions.push({
          type: "sql",
          status: "skipped",
          reason: "No rollback_sql derivable from captured state or template — cannot safely auto-apply, apply manually",
        });
      } else {
        const query = `BEGIN;\n${item.sql_to_execute.join("\n")}\nCOMMIT;`;
        try {
          await dbFn(query);
          execItem.actions.push({ type: "sql", status: "applied" });
          // Record state-capture results for the snapshot (exact rollback on restore).
          stateCaptureResults.set(item.id, { capturedState, rollbackSqlExact, rollbackExact });
        } catch (e) {
          execItem.actions.push({
            type: "sql",
            status: "failed",
            error: e.message,
          });
        }
      }
    }

    // Execute management-API PATCH actions.
    if (item.categories.hasMgmtApi) {
      const action = item.management_api_action;
      try {
        await mgmtFn(action.method, action.path, action.body);
        execItem.actions.push({ type: "mgmt_api", status: "applied" });
      } catch (e) {
        execItem.actions.push({
          type: "mgmt_api",
          status: "failed",
          error: e.message,
        });
      }
    }

    execResults.push(execItem);
  }

  // Update the snapshot with apply results so a future rollback can skip
  // items that were never successfully applied (e.g. a 402 from a paid feature
  // on free-tier — rolling back a no-op would falsely report "applied").
  if (snapshotPath) {
    const appliedIds = execResults
      .filter((r) => r.actions.some((a) => a.status === "applied"))
      .map((r) => r.id);
    try {
      const snapshotContent = readFileSync(snapshotPath, "utf8");
      const updated = JSON.parse(snapshotContent);
      updated.applied_ids = appliedIds;
      // Merge captured state + exact rollback into each plan item.
      for (const planItem of updated.plan || []) {
        const cap = stateCaptureResults.get(planItem.id);
        if (cap) {
          planItem.captured_state = cap.capturedState;
          planItem.rollback_sql_exact = cap.rollbackSqlExact;
          planItem.rollback_exact = cap.rollbackExact;
        }
      }
      _writeSnapshot(snapshotPath, JSON.stringify(updated, null, 2));
    } catch { /* non-fatal — rollback will proceed for all items as fallback */ }
  }

  return {
    project_ref: ref,
    mode: "apply",
    plan,
    results: execResults,
    summary: buildApplySummary(execResults),
    verification: await verifyRemediation(plan, execResults, verifyFn || null),
    snapshot_path: snapshotPath,
  };
}

// === ROLLBACK (entry 26: idempotency + reversibility) ===

/**
 * Build a pre-rollback snapshot of the *current* state (after a prior apply)
 * so the rollback itself is reversible. Mirrors remediate()'s snapshot shape.
 */
function buildRollbackSnapshot(ref, plan, applyResults) {
  return {
    project_ref: ref,
    timestamp: new Date().toISOString(),
    mode: "pre-rollback",
    plan: plan.map((p) => ({
      id: p.id,
      check: p.check,
      target: p.target,
      severity: p.severity,
      requires_service_role: p.requires_service_role,
      sql_to_execute: p.sql_to_execute,
      rollback_sql: p.rollback_sql,
      rollback_sql_exact: p.rollback_sql_exact || null,
      captured_state: p.captured_state || null,
      rollback_exact: p.rollback_exact || false,
      management_api_action: p.management_api_action,
      rollback_management_api_action: p.rollback_management_api_action,
      dashboard_action: p.dashboard_action,
    })),
  };
}

/**
 * Rollback a prior remediation using its snapshot (written by remediate()
 * before apply). Executes the inverse of every applied fix:
 *   - rollback_sql (executable lines only) wrapped in BEGIN/COMMIT via dbQuery
 *   - rollback_management_api_action via mgmtRequest
 *   - dashboard-only / no-rollback items are listed as skipped (cannot auto-reverse)
 *
 * Idempotent: re-running on an already-rolled-back state does not error
 * (PG REVOKE→GRANT and mgmt-API PATCH are naturally idempotent).
 *
 * @param {object} snapshot — parsed snapshot JSON from a prior remediate() --apply
 * @param {object} [opts]
 * @param {string} [opts.token] — PAT (required)
 * @param {string} [opts.ref] — overrides snapshot.project_ref
 * @param {string} [opts.service_role_key] — for findings with requires_service_role
 * @param {function} [opts._dbQuery] — injectable: (query) => Promise<any>
 * @param {function} [opts._mgmtRequest] — injectable: (method, path, body) => Promise<any>
 * @param {function} [opts._writeSnapshot] — injectable: (path, content) => void
 * @param {Set} [opts._permSet] — injectable permanent blocklist (testing the un-unblockable tier)
 * @param {Set} [opts._labSet] — injectable lab-eligible blocklist (testing)
 * @returns {Promise<object>} { project_ref, mode:"rollback", results, summary, snapshot_path? }
 */
export async function rollbackRemediation(snapshot, opts = {}) {
  const {
    token = process.env.SUPABASE_ACCESS_TOKEN,
    ref = snapshot.project_ref,
    service_role_key = process.env.SUPABASE_SERVICE_ROLE_KEY,
    _dbQuery,
    _mgmtRequest,
    _writeSnapshot,
    allowLab = false,
    destructiveAck = false,
    _permSet,
    _labSet,
  } = opts;

  const projectRef = ref || snapshot.project_ref;

  // Guard: production-ref blocklist applies to rollback too — check BEFORE token.
  if (isBlockedRef(projectRef, { allowLab, destructiveAck }, _permSet, _labSet)) {
    const err = new Error(`refusing: production ref — rollback is disabled for known production projects`);
    err.code = "PROD_REF_BLOCKED";
    throw err;
  }

  if (!token) {
    const err = new Error("Token required for rollback. Set SUPABASE_ACCESS_TOKEN or pass --token.");
    err.code = "AUTH_ERROR";
    throw err;
  }

  const plan = Array.isArray(snapshot.plan) ? snapshot.plan : [];
  const dbFn = _dbQuery || ((query) => dbQuery(token, projectRef, query));
  const mgmtFn = _mgmtRequest || ((method, path, body) => mgmtRequest(token, method, path, body));

  // Snapshot the current (post-apply) state so the rollback itself is reversible.
  let rollbackSnapshotPath = null;
  if (_writeSnapshot && plan.length > 0) {
    const preRollback = buildRollbackSnapshot(projectRef, plan, []);
    rollbackSnapshotPath = `fixtures/remediation_snapshot_pre_rollback_${Date.now()}.json`;
    _writeSnapshot(rollbackSnapshotPath, JSON.stringify(preRollback, null, 2));
  }

  // Execute rollbacks in severity order (match apply ordering for determinism).
  const severitySorted = [...plan].sort((a, b) => {
    const sa = SEVERITY_RANK[a.severity] ?? 99;
    const sb = SEVERITY_RANK[b.severity] ?? 99;
    if (sa !== sb) return sa - sb;
    if (a.check !== b.check) return a.check < b.check ? -1 : 1;
    return a.target < b.target ? -1 : a.target > b.target ? 1 : 0;
  });

  const results = [];
  const hasAppliedIds = Array.isArray(snapshot.applied_ids);
  const appliedIds = new Set(hasAppliedIds ? snapshot.applied_ids : []);
  for (const item of severitySorted) {
    const execItem = {
      id: item.id,
      check: item.check,
      target: item.target,
      severity: item.severity,
      actions: [],
    };

    // Skip rollback for items that were never successfully applied.
    // Distinguish: applied_ids present-but-empty (nothing applied) from
    // applied_ids absent (legacy snapshot, fall back to full rollback).
    if (hasAppliedIds && !appliedIds.has(item.id)) {
      execItem.actions.push({
        type: "rollback_skip",
        status: "skipped",
        reason: "This fix was not successfully applied — nothing to roll back",
      });
      results.push(execItem);
      continue;
    }

    // Executable rollback SQL — prefer the exact rollback derived from captured
    // pre-apply ACL state (rollback_sql_exact); fall back to the template
    // rollback_sql when state capture was unavailable (rollback_exact: false).
    const exactRollback = Array.isArray(item.rollback_sql_exact) && item.rollback_sql_exact.length > 0
      ? item.rollback_sql_exact
      : null;
    const fallbackRollback = Array.isArray(item.rollback_sql) ? item.rollback_sql : [];
    const rollbackSql = (exactRollback || fallbackRollback).filter(isExecutableSql);
    const rollbackExact = !!exactRollback;
    const hasRollbackSql = rollbackSql.length > 0;
    const hasRollbackMgmt = !!item.rollback_management_api_action;

    // Dashboard-only items: the fix had only a human click-path — can't auto-reverse.
    const isDashboardOnly = !hasRollbackSql && !hasRollbackMgmt && !!item.dashboard_action;
    if (isDashboardOnly) {
      execItem.actions.push({
        type: "dashboard_skip",
        status: "skipped",
        click_path: item.dashboard_action,
      });
      results.push(execItem);
      continue;
    }

    // service_role guard: re-granting revoked privileges may require the service_role.
    if (item.requires_service_role && !service_role_key) {
      // If there's rollback SQL that needs the service_role, skip it.
      if (hasRollbackSql) {
        execItem.actions.push({
          type: "sql_rollback",
          status: "skipped",
          reason: "requires_service_role is true but no service_role key provided — apply manually",
        });
      }
      if (hasRollbackMgmt) {
        try {
          await mgmtFn(
            item.rollback_management_api_action.method,
            item.rollback_management_api_action.path,
            item.rollback_management_api_action.body
          );
          execItem.actions.push({ type: "mgmt_api_rollback", status: "applied" });
        } catch (e) {
          execItem.actions.push({ type: "mgmt_api_rollback", status: "failed", error: e.message });
        }
      }
      results.push(execItem);
      continue;
    }

    // Execute rollback SQL (wrapped in its own transaction per finding).
    if (hasRollbackSql) {
      const query = `BEGIN;\n${rollbackSql.join("\n")}\nCOMMIT;`;
      try {
        await dbFn(query);
        execItem.actions.push({ type: "sql_rollback", status: "applied" });
      } catch (e) {
        execItem.actions.push({ type: "sql_rollback", status: "failed", error: e.message });
      }
    } else if (!hasRollbackMgmt) {
      execItem.actions.push({ type: "sql_rollback", status: "skipped", reason: "No rollback SQL available" });
    }

    // Execute rollback management-API action.
    if (hasRollbackMgmt) {
      try {
        await mgmtFn(
          item.rollback_management_api_action.method,
          item.rollback_management_api_action.path,
          item.rollback_management_api_action.body
        );
        execItem.actions.push({ type: "mgmt_api_rollback", status: "applied" });
      } catch (e) {
        execItem.actions.push({ type: "mgmt_api_rollback", status: "failed", error: e.message });
      }
    }

    results.push(execItem);
  }

  return {
    project_ref: projectRef,
    mode: "rollback",
    snapshot_path: rollbackSnapshotPath,
    pre_rollback_snapshot_path: snapshot.snapshot_path || null,
    results,
    summary: {
      total: results.length,
      applied: results.filter((r) => r.actions.some((a) => a.status === "applied")).length,
      failed: results.filter((r) => r.actions.some((a) => a.status === "failed")).length,
      skipped: results.filter((r) => r.actions.some((a) => a.status === "skipped")).length,
    },
  };
}

// === CLI ===

async function main() {
  // Merge .supa360.json ref protection into env BEFORE any guard check.
  try {
    applyRefConfig();
  } catch (e) {
    console.error(`remediate: ${e.message}`);
    return EXIT_CODES.SCHEMA_VIOLATION;
  }

  const args = process.argv.slice(2);

  if (args.includes("--help") || args.includes("-h")) {
    console.error(`Usage:
  supabase-security remediate <result.json> [--apply] [--token <tok>] [--yes]
  supabase-security remediate <snapshot.json> --rollback [--token <tok>] [--yes]
  cat result.json | node scripts/remediate.js [--apply] [--token <tok>] [--yes]

  Consumes a prior JSON audit result and produces a remediation plan.
  Default is DRY-RUN (prints plan, does nothing).

Flags:
  --apply            Execute fixes (dry-run is the default; no side effects without this)
  --rollback         Rollback a prior --apply using its snapshot file (reverses the fix)
  --yes              Skip confirmation prompt (required with --apply/--rollback in non-interactive mode)
  --token <tok>      Supabase PAT — required for --apply/--rollback (or SUPABASE_ACCESS_TOKEN env)
  --service-role <key>  service_role key for findings requiring it (or SUPABASE_SERVICE_ROLE_KEY env)
  --i-understand-this-is-destructive  Acknowledge destructive action (required for lab-blocked refs; requires SUPA360_LAB_REF env matching the ref)
  --help, -h         Show this help

Guards:
  - Refs listed in SUPA360_PERMANENT_BLOCKED_REFS can NEVER be remediated or used as
    a lab. No flag or env combination unblocks them — not even SUPA360_LAB_REF naming
    that same ref. PUT YOUR PRODUCTION REFS HERE.
  - Refs listed in SUPA360_BLOCKED_REFS (disposable lab projects) are blocked from
    --apply and --rollback UNLESS env SUPA360_LAB_REF=<same ref> AND
    --i-understand-this-is-destructive are both present. NEVER list production here —
    this tier is unblockable by ceremony, by design.
  - Both are unset by default. This tool cannot know which of your projects is production
    — you declare it. Nothing is blocked until you do.
  - --apply / --rollback on a TTY prompts for confirmation; --yes skips it
  - Findings without rollback_sql are skipped (manual)
  - Findings with requires_service_role=true need --service-role

Exit codes:
  0  Success — plan printed (dry-run) or all fixable findings applied/rolled-back
  2  Some findings failed during --apply / --rollback
  10 Auth error — token missing or rejected (401/403)
  11 Network error — DNS/connection failure
  12 Input validation failure (invalid JSON, missing project_ref, etc.)`);
    process.exit(0);
  }

  const applyMode = args.includes("--apply");
  const rollbackMode = args.includes("--rollback");
  const yesMode = args.includes("--yes");
  const destructiveAck = args.includes("--i-understand-this-is-destructive");
  const allowLab = destructiveAck && !!process.env.SUPA360_LAB_REF;
  const tokenArg = args.includes("--token") ? args[args.indexOf("--token") + 1] : null;
  const token = tokenArg || process.env.SUPABASE_ACCESS_TOKEN;
  const serviceRoleArg = args.includes("--service-role") ? args[args.indexOf("--service-role") + 1] : null;
  const serviceRoleKey = serviceRoleArg || process.env.SUPABASE_SERVICE_ROLE_KEY;
  const filePath = args.find((a) => !a.startsWith("--"));

  // Read JSON result: from file argument, or stdin if piped.
  let result;
  try {
    if (filePath) {
      result = JSON.parse(readFileSync(filePath, "utf8"));
    } else if (!process.stdin.isTTY) {
      let input = "";
      process.stdin.setEncoding("utf8");
      for await (const chunk of process.stdin) {
        input += chunk;
      }
      result = JSON.parse(input);
    } else {
      console.error("remediate: provide a result file path or pipe JSON via stdin");
      console.error("  e.g. node scripts/remediate.js audit-result.json");
      console.error("  e.g. node scripts/audit.js <ref> --json | node scripts/remediate.js");
      process.exit(EXIT_CODES.SCHEMA_VIOLATION);
    }
  } catch (e) {
    console.error(`remediate: cannot parse JSON input: ${e.message}`);
    process.exit(EXIT_CODES.SCHEMA_VIOLATION);
  }

  // Validate basic structure
  if (!result || typeof result !== "object") {
    console.error("remediate: input is not a JSON object");
    process.exit(EXIT_CODES.SCHEMA_VIOLATION);
  }
  if (!result.project_ref) {
    console.error("remediate: input JSON missing project_ref");
    process.exit(EXIT_CODES.SCHEMA_VIOLATION);
  }

  // --rollback reads a snapshot file (needs .plan[]); apply/dry-run reads an audit result (needs .findings[])
  if (rollbackMode) {
    if (!Array.isArray(result.plan)) {
      console.error("remediate --rollback: snapshot JSON missing plan array");
      console.error("  e.g. node scripts/remediate.js fixtures/remediation_snapshot_<ts>.json --rollback --yes --token <tok>");
      process.exit(EXIT_CODES.SCHEMA_VIOLATION);
    }
  } else {
    if (!Array.isArray(result.findings)) {
      console.error("remediate: input JSON missing findings array");
      process.exit(EXIT_CODES.SCHEMA_VIOLATION);
    }
  }

  const ref = result.project_ref;

  // Confirmation guard: --apply / --rollback in non-interactive mode requires --yes.
  if (applyMode || rollbackMode) {
    const verb = rollbackMode ? "ROLLBACK" : "apply fixes";
    if (process.stdin.isTTY && !yesMode) {
      const answer = await promptConfirm(
        `About to ${verb} on project ${ref}. Type 'yes' to confirm: `
      );
      if (answer !== "yes") {
        console.error(`remediate: ${rollbackMode ? "rollback" : "apply"} aborted by user.`);
        process.exit(EXIT_CODES.CLEAN);
      }
    } else if (!yesMode) {
      console.error(`remediate: --${rollbackMode ? "rollback" : "apply"} requires --yes in non-interactive mode (no TTY).`);
      console.error(`  e.g. node scripts/remediate.js snapshot.json --${rollbackMode ? "rollback" : "apply"} --yes --token <tok>`);
      process.exit(EXIT_CODES.SCHEMA_VIOLATION);
    }
  }

  try {
    let remediation;

    if (rollbackMode) {
      // Reverse a prior --apply using its snapshot file.
      remediation = await rollbackRemediation(result, {
        token,
        ref,
        service_role_key: serviceRoleKey,
        _writeSnapshot: defaultWriteSnapshot,
        allowLab,
        destructiveAck,
      });
    } else {
      remediation = await remediate(result, {
        dryRun: !applyMode,
        token,
        ref,
        service_role_key: serviceRoleKey,
        _writeSnapshot: defaultWriteSnapshot,
        allowLab,
        destructiveAck,
      });
    }

    // Scan output for secrets before printing (contract: no secrets ever in output)
    const output = JSON.stringify(remediation, null, 2);
    const secrets = scanForSecrets(output);
    if (secrets.length > 0) {
      console.error(`remediate: SECRET LEAK detected in output: ${JSON.stringify(secrets)}`);
      process.exit(EXIT_CODES.SCHEMA_VIOLATION);
    }

    console.log(output);

    if (applyMode || rollbackMode) {
      if (remediation.snapshot_path) {
        const label = rollbackMode ? "pre-rollback snapshot" : "snapshot";
        console.error(`remediate: ${label} written to ${remediation.snapshot_path}`);
      }
      const failed = remediation.summary.failed || 0;
      const skipped = remediation.summary.skipped || 0;
      if (skipped > 0) {
        console.error(`remediate: ${skipped} finding(s) skipped — review in output above (dashboard-only / no-rollback / requires_service_role).`);
      }
      if (failed > 0) {
        process.exit(EXIT_CODES.FINDINGS);
      }
      process.exit(EXIT_CODES.CLEAN);
    }
    process.exit(EXIT_CODES.CLEAN);
  } catch (e) {
    if (e.code === "AUTH_ERROR") {
      console.error(e.message);
      process.exit(EXIT_CODES.AUTH_ERROR);
    }
    if (e.code === "PROD_REF_BLOCKED") {
      console.error(e.message);
      process.exit(EXIT_CODES.SCHEMA_VIOLATION);
    }
    const classification = classifyError(e);
    if (classification === "auth_error") {
      console.error(e.message);
      process.exit(EXIT_CODES.AUTH_ERROR);
    }
    if (classification === "network_error") {
      console.error(e.message);
      process.exit(EXIT_CODES.NETWORK_ERROR);
    }
    console.error(e.message);
    process.exit(1);
  }
}

// Guard process.argv[1] for safe import as a library (e.g. from tests or lab.js).
const argv1 = process.argv[1] || "";
const isCliEntry =
  import.meta.url === `file://${argv1.replace(/\\/g, "/")}` ||
  (argv1 && import.meta.url.endsWith(argv1.replace(/\\/g, "/")));

if (isCliEntry) {
  main().catch((e) => {
    console.error(e?.message || e);
    process.exit(1);
  });
}

export { main, refHash, BLOCKED_REF_HASHES, PERMANENT_BLOCKED_REF_HASHES, LAB_ELIGIBLE_REF_HASHES };
