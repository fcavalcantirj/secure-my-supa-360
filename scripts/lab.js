#!/usr/bin/env node
// scripts/lab.js — Lab management for the skill's WRITE-path validation.
//
// Provides a safe, reversible way to seed a disposable Supabase project
// with fixtures/seed.sql, run the full audit → remediate → rollback → audit
// cycle, and emit a per-check matrix proving detection + remediation + rollback.
//
// Safety: the blocklist is NOT disabled. A prod ref stays blocked unless BOTH:
//   env SUPA360_LAB_REF=<ref>      (must match the target ref exactly)
//   --i-understand-this-is-destructive           (explicit CLI flag)
// are present. The env var alone never suffices; naming one blocked ref never
// unblocks a different one.

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

import { audit } from "./audit.js";
import {
  remediate, rollbackRemediation, isBlockedRef, dbQuery, refHash, envNamesRef,
  PERMANENT_BLOCKED_REF_HASHES, LAB_ELIGIBLE_REF_HASHES, isExecutableSql,
} from "./remediate.js";
import { EXIT_CODES } from "./contract.js";
import { loadSuppressions } from "./suppress.js";
import { captureState, isDefaultPrivFor } from "./checks/state.js";
import { applyRefConfig } from "./refconfig.js";

const ROOT = dirname(dirname(fileURLToPath(import.meta.url)));
const SEED_PATH = join(ROOT, "fixtures", "seed.sql");
const TEARDOWN_PATH = join(ROOT, "fixtures", "teardown.sql");
const API = "https://api.supabase.com/v1";

// --- Lab ref allowlist (WO-19c: two-tier blocklist) ---

/**
 * Check if a ref is permitted for lab operations.
 *
 * Two-tier blocklist:
 *  - PERMANENT_BLOCKED_REF_HASHES: production refs that are NEVER unblocked.
 *    Checked first — env var + flag cannot override these.
 *  - LAB_ELIGIBLE_REF_HASHES + SUPA360_BLOCKED_REFS: blocked by default but
 *    unblocked when BOTH env SUPA360_LAB_REF=<ref> AND --i-understand-this-is-destructive.
 *
 * Naming one blocked ref never unblocks a different one (hash comparison).
 *
 * @param {string} ref — project ref
 * @param {boolean} destructiveAck — whether --i-understand-this-is-destructive was passed
 * @returns {{allowed: boolean, reason: string|null, isProd: boolean}}
 */
export function checkLabRef(ref, destructiveAck) {
  // Tier 1 (permanent) is sourced from the shipped/injected set AND from
  // SUPA360_PERMANENT_BLOCKED_REFS — a production ref listed there can NEVER be
  // used as a lab, under any ceremony. Tier 2 (SUPA360_BLOCKED_REFS) is unblockable
  // by full ceremony, so production must never be listed there.
  const isProdRef =
    PERMANENT_BLOCKED_REF_HASHES.has(refHash(ref)) ||
    envNamesRef("SUPA360_PERMANENT_BLOCKED_REFS", ref);
  const isLabEligible =
    LAB_ELIGIBLE_REF_HASHES.has(refHash(ref)) ||
    envNamesRef("SUPA360_BLOCKED_REFS", ref);

  // Non-blocked refs still require the destructive flag for lab commands.
  if (!isProdRef && !isLabEligible) {
    if (!destructiveAck) {
      return {
        allowed: false,
        reason: "lab commands require --i-understand-this-is-destructive (this operation is irreversible)",
        isProd: false,
      };
    }
    return { allowed: true, reason: null, isProd: false };
  }

  // Lab commands always require the flag, even for blocked refs.
  if (!destructiveAck) {
    return {
      allowed: false,
      reason: "lab commands require --i-understand-this-is-destructive (this operation is irreversible)",
      isProd: isProdRef,
    };
  }

  // PERMANENT: production ref — NEVER allow, even with lab ceremony.
  if (isProdRef) {
    return {
      allowed: false,
      reason: `PRODUCTION ref ${ref} is permanently blocked — cannot be used as a lab under any circumstances`,
      isProd: true,
    };
  }

  // Lab-eligible: check that SUPA360_LAB_REF matches this exact ref.
  const labRef = process.env.SUPA360_LAB_REF;
  if (!labRef) {
    return {
      allowed: false,
      reason: `blocked ref ${ref} requires SUPA360_LAB_REF=${ref} AND --i-understand-this-is-destructive`,
      isProd: false,
    };
  }

  if (refHash(labRef) !== refHash(ref)) {
    return {
      allowed: false,
      reason: `SUPA360_LAB_REF (${labRef}) does not match target ref (${ref}) — a different project cannot be unblocked`,
      isProd: false,
    };
  }

  return { allowed: true, reason: null, isProd: false };
}

// --- Lab operations ---

/** Read a SQL fixture file and return its contents as a string. */
function readSqlFixture(path) {
  return readFileSync(path, "utf8");
}

/** Apply fixtures/seed.sql to the lab project (single SQL batch). */
export async function seedLab(token, ref) {
  const sql = readSqlFixture(SEED_PATH);
  try {
    await dbQuery(token, ref, sql);
  } catch (e) {
    throw new Error(`lab: seed SQL failed: ${e.message || String(e)}`);
  }
  console.error(`lab: seeded ${SEED_PATH} onto ${ref}`);
  return { seeded: true, ref, lines: sql.split("\n").length };
}

/** Split SQL into individual statements (naive splitter: splits on `;` at line start). */
function splitSqlStatements(sql) {
  return sql
    .split("\n")
    .filter((line) => {
      const t = line.trim();
      return t && !t.startsWith("--");
    })
    .join("\n")
    .split(";")
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
}

/**
 * Apply fixtures/teardown.sql to the lab project — cleans up all seeded objects.
 * Executes statements individually, continuing on error. The storage bucket
 * is deleted via the Storage API (SQL DELETE is blocked by storage.protect_delete()).
 * Returns a report of what succeeded and what failed.
 */
export async function teardownLab(token, ref) {
  const sql = readSqlFixture(TEARDOWN_PATH);
  const statements = splitSqlStatements(sql);
  const results = { ref, results: [], errors: [], bucket_deleted: false };

  for (const stmt of statements) {
    try {
      await dbQuery(token, ref, stmt);
      results.results.push({ statement: stmt.slice(0, 60), ok: true });
    } catch (e) {
      results.errors.push({ statement: stmt.slice(0, 60), error: e.message || String(e) });
      results.results.push({ statement: stmt.slice(0, 60), ok: false, error: e.message });
    }
  }

  // Delete the storage bucket via Storage API (SQL DELETE is blocked by storage.protect_delete()).
  // Must empty the bucket first (DELETE /v1/bucket/{id} returns 400 if non-empty).
  // Use service_role key (not anon) — anon can't delete from private buckets (403).
  try {
    const SUPABASE_URL = `https://${ref}.supabase.co`;
    // Fetch all API keys (including service_role) from Management API.
    const keysRes = await fetch(`${API}/projects/${ref}/api-keys?reveal=true`, {
      headers: { Authorization: `Bearer ${token}`, "User-Agent": "supabase-security/0.4-lab" },
    });
    const keys = keysRes.ok ? await keysRes.json() : [];
    const serviceKey = Array.isArray(keys) ? keys.find((k) => k.name === "service_role") : null;
    const serviceRoleKey = serviceKey?.api_key || process.env.SUPABASE_SERVICE_ROLE_KEY || null;

    const authHeaders = {
      "Content-Type": "application/json",
      "User-Agent": "supabase-security/0.4-lab",
      ...(serviceRoleKey ? { apikey: serviceRoleKey, Authorization: `Bearer ${serviceRoleKey}` } : {}),
    };

    if (!serviceRoleKey) {
      results.errors.push({ statement: "DELETE bucket:media (Storage API)", error: "No service_role key available — cannot empty/delete bucket" });
    } else {
      // 0. Check if the bucket exists (GET /v1/bucket/{id})
      const getRes = await fetch(`${SUPABASE_URL}/storage/v1/bucket/media`, {
        method: "GET", headers: authHeaders,
      });
      results.bucket_existed = getRes.ok;

      if (getRes.ok) {
        // 1. Empty the bucket (POST /storage/v1/bucket/{id}/empty)
        const emptyRes = await fetch(`${SUPABASE_URL}/storage/v1/bucket/media/empty`, {
          method: "POST", headers: authHeaders,
        });
        if (!emptyRes.ok) {
          results.errors.push({ statement: "empty bucket:media (Storage API)", error: `HTTP ${emptyRes.status}` });
        }

        // 2. Delete the bucket (DELETE /storage/v1/bucket/{id})
        const delRes = await fetch(`${SUPABASE_URL}/storage/v1/bucket/media`, {
          method: "DELETE", headers: authHeaders,
        });
        if (delRes.ok) {
          results.bucket_deleted = true;
        } else {
          results.errors.push({ statement: "DELETE bucket:media (Storage API)", error: `HTTP ${delRes.status}` });
        }
      }
      // If bucket doesn't exist (getRes.not ok), that's fine — nothing to delete.
    }
  } catch (e) {
    results.errors.push({ statement: "DELETE bucket:media (Storage API)", error: e.message || String(e) });
  }

  if (results.errors.length > 0) {
    console.error(`lab: teardown: ${results.errors.length} step(s) could not complete:`);
    for (const err of results.errors) {
      console.error(`  - ${err.statement}: ${err.error}`);
    }
  }
  console.error(`lab: teardown complete — ${results.results.length - results.errors.length}/${results.results.length} SQL steps, bucket_deleted=${results.bucket_deleted}`);

  return results;
}

// --- Matrix (WO-19b headline feature) ---

/**
 * Run the full end-to-end lab matrix:
 *   seed → audit (detect) → remediate --apply (fix) → audit (verify fixed)
 *       → remediate --rollback (restore) → audit (verify restored)
 *       → teardown (clean)
 *
 * Emits a per-check matrix: check → SEEDED → DETECTED → FIXED → ROLLBACK_EXACT → TEARDOWN_CLEAN
 */

// captureState and isDefaultPrivFor are imported from ./checks/state.js (shared with remediate.js).
// They were previously inlined here as lab-only and are now unified so the lab
// matrix and user-facing --apply path use the same ACL capture logic.

export async function runMatrix(token, ref, opts = {}) {
  const { includeSystemSchemas = false } = opts;
  const suppressions = loadSuppressions(process.cwd());
  const auditOpts = { activeProbe: false, suppressions, includeSystemSchemas };

  console.error(`lab: starting matrix on ${ref}`);

  // Phase 0: Teardown any existing state (idempotency — prevents 42P07 on re-run)
  console.error("lab: teardown (pre-seed cleanup) ...");
  let preSeedTeardown = null;
  try {
    preSeedTeardown = await teardownLab(token, ref);
    if ((preSeedTeardown.errors || []).length > 0) {
      console.error(`lab: pre-seed teardown had ${(preSeedTeardown.errors || []).length} issue(s) — continuing (lab is disposable)`);
    }
  } catch (e) {
    console.error(`lab: pre-seed teardown skipped (${e.message || e})`);
  }

  // Phase 0.5: Baseline audit (pre-seed) — classify findings as PRE_EXISTING vs SQL-SEEDED.
  // Auth-config, Data-API, realtime-broadcast checks etc. are seeded by project config
  // defaults, not SQL — the baseline captures them so they don't read as "seeded".
  console.error("lab: audit (baseline, pre-seed) ...");
  const baseline = await audit(token, ref, auditOpts);
  const baselineIds = new Set((baseline.findings || []).map((f) => f.id));

  // Phase 1: Seed
  console.error("lab: seed ...");
  await seedLab(token, ref);

  // Phase 2: Audit (detect — expect findings)
  console.error("lab: audit (post-seed) ...");
  const before = await audit(token, ref, auditOpts);
  const beforeFindings = before.findings || [];

  // WO-19b: classify expected checks as SQL-SEEDABLE or CONFIG-DEPENDENT.
  // Config-dependent checks (e.g. custom_schema_exposed needs PostgREST db_schema)
  // cannot be seeded via SQL — report as UNTESTABLE, do not fail the matrix.
  const SQL_SEEDABLE_CHECKS = new Set([
    "rls_disabled",                          // public_notes: RLS OFF + anon grants
    "rls_permissive_policy",                 // sensitive_photos: RLS ON + USING(true) + anon SELECT
    "rls_permissive_write_policy",           // comments: permissive INSERT WITH CHECK
    "function_secdef_missing_auth_check",     // attach_company_admin: no auth check
    "function_secdef_dynamic_sql",            // attach_company_admin: EXECUTE without USING
    "function_no_search_path",                // secdef function without SET search_path
    "function_secdef_no_search_path",         // secdef function body without search_path
    "view_security_definer_bypass",           // v_tenant_data: security_invoker over RLS table
    "storage_bucket_public",                  // media bucket: public
    "column_grant_exposes_column",           // user_profiles: anon SELECT on email
    "default_privileges_not_revoked",         // future tables to anon
  ]);
  const CONFIG_DEPENDENT_CHECKS = new Set([
    "custom_schema_exposed",                  // requires PostgREST db_schema config (not SQL)
  ]);

  if (beforeFindings.length === 0) {
    throw new Error("lab matrix: seed produced ZERO findings — the fixture is broken.");
  }
  const beforeChecks = new Set(beforeFindings.map((f) => f.check));
  const missingSeedable = [...SQL_SEEDABLE_CHECKS].filter((c) => !beforeChecks.has(c));
  if (missingSeedable.length > 0) {
    const missingList = missingSeedable.join(", ");
    throw new Error(`lab matrix: seed did not produce SQL-seedable checks: ${missingList}. Fix seed.sql or the check.`);
  }

  // Phase 2.5: Capture pre-apply DB state for each finding (WO-19 Bug 1 —
  // state-based rollback verification, not just finding presence).
  // This catches the WO-5 class of bug: rollback restores the finding while
  // silently widening access (e.g. USAGE+SELECT where only SELECT was captured).
  const preStates = new Map();
  for (const f of beforeFindings) {
    const state = await captureState(token, ref, f, (q) => dbQuery(token, ref, q));
    if (state) preStates.set(f.id, state);
  }

  // Phase 3: Remediate (apply)
  console.error("lab: remediate --apply ...");
  const applyResult = await remediate(before, {
    dryRun: false,
    token,
    ref,
    allowLab: true,
    destructiveAck: true,
  });
  const snapshot = applyResult.snapshot_path
    ? JSON.parse(readFileSync(applyResult.snapshot_path, "utf8"))
    : applyResult;

  // Phase 4: Audit (verify fixed)
  console.error("lab: audit (post-apply) ...");
  const after = await audit(token, ref, auditOpts);
  const afterFindings = after.findings || [];
  const afterIds = new Set(afterFindings.map((f) => f.id));

  // Phase 5: Rollback
  console.error("lab: remediate --rollback ...");
  await rollbackRemediation(snapshot, {
    token,
    ref,
    allowLab: true,
    destructiveAck: true,
  });

  // Phase 6: Audit (verify restored)
  console.error("lab: audit (post-rollback) ...");
  const restored = await audit(token, ref, auditOpts);
  const restoredFindings = restored.findings || [];
  const restoredIds = new Set(restoredFindings.map((f) => f.id));

  // Phase 6.5: Capture post-rollback DB state — compare against pre-apply.
  const postStates = new Map();
  for (const f of restoredFindings) {
    const state = await captureState(token, ref, f, (q) => dbQuery(token, ref, q));
    if (state) postStates.set(f.id, state);
  }

  // Phase 7: Teardown
  console.error("lab: teardown ...");
  let teardownResult = null;
  try {
    teardownResult = await teardownLab(token, ref);
  } catch (e) {
    console.error(`lab: teardown failed: ${e.message}`);
  }
  // teardownClean: true only if BOTH pre-seed and post-seed teardowns succeeded.
  // A pre-seed teardown failure (e.g. bucket non-empty from a prior run) means
  // the lab cannot reliably reset — that is a lie we must surface.
  const preSeedClean = !preSeedTeardown ||
    ((preSeedTeardown.errors || []).length === 0 && (preSeedTeardown.bucket_deleted || !preSeedTeardown.bucket_existed));
  const postSeedClean = teardownResult
    ? (teardownResult.errors.length === 0 && (teardownResult.bucket_deleted || !teardownResult.bucket_existed))
    : false;
  const teardownClean = preSeedClean && postSeedClean;

  // --- Build the matrix table: per-check -> SEEDED -> DETECTED -> FIXED -> ROLLBACK_EXACT -> TEARDOWN_CLEAN ---
  const beforeIds = new Set(beforeFindings.map((f) => f.id));

  // Helper: determine fix type from the finding's fix object.
  // Uses isExecutableSql to distinguish real SQL from comment-only guidance.
  const fixType = (f) => {
    const fix = f?.fix || {};
    const hasExecutableSql = Array.isArray(fix.sql) && fix.sql.some((s) => isExecutableSql(s));
    if (hasExecutableSql) return "sql";
    if (Array.isArray(fix.sql) && fix.sql.length > 0) return "advisory"; // comments only — human must act
    if (fix.dashboard_action) return "dashboard_only";
    if (fix.management_api_action) return "management_api";
    return "none";
  };

  const matrix = [];

  // SQL-seedable checks: must be detected, fixed, and rollback-exact.
  // rollback_exact is null when the fix was never applied (finding still present
  // after apply) — a bare true would be dishonest and hide WO-5-style misses.
  for (const check of SQL_SEEDABLE_CHECKS) {
    const bf = beforeFindings.find((f) => f.check === check);
    const af = afterFindings.find((f) => f.check === check);
    const rf = restoredFindings.find((f) => f.check === check);
    const target = (bf || af || rf)?.target || "(multi)";
    const severity = (bf || af || rf)?.severity || "unknown";
    const wasFixed = !!bf && !af;
    // State-based rollback verification: compare pre-apply and post-rollback DB state.
    // A finding that reappears but with wider grants would pass finding-based check
    // but FAIL state comparison — this is the WO-5 catch.
    const preState = preStates.get(bf?.id);
    const postState = postStates.get(bf?.id);
    const canVerify = preState && postState;
    const stateMatch = canVerify && JSON.stringify(preState) === JSON.stringify(postState);
    const rollbackRow = {
      check, target, severity,
      seeded: bf ? "SQL" : "SQL (MISSING -- seed did not trigger this check)",
      detected: !!bf,
      fixed: wasFixed,
      // true: fixed AND state matches; false: fixed but state differs; null: not fixed or can't capture state
      rollback_exact: wasFixed ? (canVerify ? (stateMatch ? true : false) : null) : null,
      fix_type: fixType(bf || af || rf || {}),
      teardown_clean: teardownClean,
    };
    // On mismatch, include both states for diagnosis
    if (wasFixed && preState && postState && !stateMatch) {
      rollbackRow.rollback_mismatch = { pre_apply: preState, post_rollback: postState };
    }
    matrix.push(rollbackRow);
  }

  // Config-dependent checks: UNTESTABLE via SQL seed
  for (const check of CONFIG_DEPENDENT_CHECKS) {
    matrix.push({
      check, target: "(config-dependent)", severity: "info",
      seeded: "UNTESTABLE",
      detected: false, fixed: false, rollback_exact: null,
      teardown_clean: teardownClean,
      untestable_reason: "Requires Management API config (not seedable via SQL)",
    });
  }

  // Any findings not in our expected set: classify as PRE_EXISTING or SQL
  for (const f of beforeFindings) {
    if (SQL_SEEDABLE_CHECKS.has(f.check) || CONFIG_DEPENDENT_CHECKS.has(f.check)) continue;
    const af = afterFindings.find((af2) => af2.id === f.id);
    const rf = restoredFindings.find((rf2) => rf2.id === f.id);
    const wasFixed = !af;
    const preState = preStates.get(f.id);
    const postState = postStates.get(f.id);
    const canVerify = preState && postState;
    const stateMatch = canVerify && JSON.stringify(preState) === JSON.stringify(postState);
    const row = {
      check: f.check, target: f.target, severity: f.severity,
      seeded: baselineIds.has(f.id) ? "PRE_EXISTING" : "SQL",
      detected: true,
      fixed: wasFixed,
      rollback_exact: wasFixed ? (canVerify ? (stateMatch ? true : false) : null) : null,
      fix_type: fixType(f),
      teardown_clean: teardownClean,
    };
    if (wasFixed && preState && postState && !stateMatch) {
      row.rollback_mismatch = { pre_apply: preState, post_rollback: postState };
    }
    matrix.push(row);
  }

  const summary = {
    total: matrix.length,
    sql_seedable: [...SQL_SEEDABLE_CHECKS].length,
    untested: [...CONFIG_DEPENDENT_CHECKS].length,
    detected: matrix.filter((m) => m.detected).length,
    fixed: matrix.filter((m) => m.fixed).length,
    rollback_exact: matrix.filter((m) => m.rollback_exact === true).length,
    rollback_mismatch: matrix.filter((m) => m.rollback_exact === false).length,
    not_applicable: matrix.filter((m) => m.rollback_exact === null).length,
    // A check that was FIXED but whose rollback could not be verified. Distinct from
    // not_applicable, which mostly counts checks that were never fixed. Conflating the
    // two is how the 2026-08-31 regression hid: rollback_exact fell 8 -> 4 while the
    // headline still read "0 mismatch". Unverified is a FAILURE, not a neutral state.
    rollback_unverified: matrix.filter((m) => m.fixed && m.rollback_exact === null).length,
    teardown_clean: teardownClean,
    pre_seed_teardown_clean: preSeedTeardown
      ? (preSeedTeardown.errors.length === 0 && (preSeedTeardown.bucket_deleted || !preSeedTeardown.bucket_existed))
      : null,
  };

  console.error(`lab: matrix complete — ${summary.detected} detected, ${summary.fixed} fixed, ${summary.rollback_exact} rollback-exact, ${summary.rollback_mismatch} mismatch, ${summary.rollback_unverified} UNVERIFIED, ${summary.not_applicable} n/a, teardown: ${teardownClean}`);
  if (summary.rollback_unverified > 0) {
    const names = matrix.filter((m) => m.fixed && m.rollback_exact === null).map((m) => m.check).join(", ");
    console.error(`lab: FAIL — ${summary.rollback_unverified} fixed check(s) had NO rollback verification: ${names}`);
    console.error("lab: a fix whose rollback cannot be verified is not proven reversible — treat as a failure, not as n/a.");
  }

  return { matrix, summary };
}

// --- CLI entry point ---

async function main() {
  // Merge .supa360.json ref protection into env BEFORE any guard check (fails loud
  // on a malformed config rather than silently dropping production protection).
  try {
    applyRefConfig();
  } catch (e) {
    console.error(`lab: ${e.message}`);
    return EXIT_CODES.SCHEMA_VIOLATION;
  }

  const args = process.argv.slice(2);

  if (args.length === 0 || args[0] === "--help" || args[0] === "-h") {
    console.error(`Usage: supabase-security lab <command> <ref> [flags]

Commands:
  lab seed <ref>        Apply fixtures/seed.sql to a lab project
  lab teardown <ref>    Apply fixtures/teardown.sql (cleans up all seeded objects)
  lab matrix <ref>      Full end-to-end: seed → audit → remediate --apply → audit → rollback → audit → teardown

Safety:
  Lab commands are DESTRUCTIVE. For production-blocked refs, both are required:
    env SUPA360_LAB_REF=<ref>   AND  --i-understand-this-is-destructive
  The env var must match the target ref exactly. A different blocked ref stays blocked.

  node scripts/lab.js seed <ref> --i-understand-this-is-destructive
  SUPA360_LAB_REF=ref node scripts/lab.js matrix <ref> --i-understand-this-is-destructive
`);
    return EXIT_CODES.CLEAN;
  }

  const command = args[0];
  if (command !== "seed" && command !== "teardown" && command !== "matrix") {
    console.error(`lab: unknown command '${command}'. Use 'seed', 'teardown', or 'matrix'.`);
    return EXIT_CODES.SCHEMA_VIOLATION;
  }

  const refIdx = args.indexOf(command) + 1;
  const ref = args[refIdx] && !args[refIdx].startsWith("--") ? args[refIdx] : null;
  const destructiveAck = args.includes("--i-understand-this-is-destructive");

  if (!ref) {
    console.error(`lab ${command}: provide a project ref`);
    console.error(`  e.g. node scripts/lab.js ${command} <ref> --i-understand-this-is-destructive`);
    return EXIT_CODES.SCHEMA_VIOLATION;
  }

  // Safety gate: check lab ref allowlist
  const gate = checkLabRef(ref, destructiveAck);
  if (!gate.allowed) {
    console.error(`lab: BLOCKED — ${gate.reason}`);
    return EXIT_CODES.SCHEMA_VIOLATION;
  }

  const token = process.env.SUPABASE_ACCESS_TOKEN || (args.includes("--token") ? args[args.indexOf("--token") + 1] : null);
  if (!token) {
    console.error("lab: SUPABASE_ACCESS_TOKEN env var or --token flag is required");
    return EXIT_CODES.AUTH_ERROR;
  }

  try {
    let teardownErrors = 0;
    if (command === "seed") {
      const result = await seedLab(token, ref);
      console.log(JSON.stringify(result, null, 2));
    } else if (command === "teardown") {
      const result = await teardownLab(token, ref);
      console.log(JSON.stringify(result, null, 2));
      teardownErrors = (result.errors || []).length;
    } else if (command === "matrix") {
      const result = await runMatrix(token, ref);
      if (!result.summary.teardown_clean) teardownErrors = 1;
      // An unverified or mismatched rollback fails the matrix. Exiting 0 here would
      // let "we verified nothing" pass for "we verified everything".
      if (result.summary.rollback_unverified > 0 || result.summary.rollback_mismatch > 0) teardownErrors = 1;
      console.log(JSON.stringify(result, null, 2));
    }
    // Non-zero exit if anything failed (Bug 5: don't exit 0 with errors in output)
    if (teardownErrors > 0) {
      console.error(`lab: completed with ${teardownErrors} error(s) — see output above`);
      return EXIT_CODES.FINDINGS;
    }
  } catch (e) {
    if (e.code === "PROD_REF_BLOCKED") {
      console.error(`lab: BLOCKED — ${e.message}`);
      return EXIT_CODES.SCHEMA_VIOLATION;
    }
    console.error(`lab: ${e.message || e}`);
    return EXIT_CODES.FINDINGS;
  }

  return EXIT_CODES.CLEAN;
}

// Guard process.argv[1] for safe import as a library.
const argv1 = process.argv[1] || "";
const isCliEntry =
  import.meta.url === `file://${argv1.replace(/\\/g, "/")}` ||
  (argv1 && import.meta.url.endsWith(argv1.replace(/\\/g, "/")));

if (isCliEntry) {
  main().then((code) => {
    process.exit(code ?? 0);
  }).catch((e) => {
    console.error(e?.message || e);
    return EXIT_CODES.SCHEMA_VIOLATION;
  });
}

export { main as labMain };
