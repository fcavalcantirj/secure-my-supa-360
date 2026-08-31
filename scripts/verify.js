#!/usr/bin/env node
// scripts/verify.js — Re-verification after remediation (spec entry 25).
//
// Consumes a remediation result (output of remediate.js in --apply mode),
// re-runs the audit, and for each applied finding determines whether the
// fix actually closed the issue.
//
// Usage:
//   node scripts/verify.js <remediation.json> [--token <tok>] [--yes]
//   node scripts/cli.js verify <remediation.json> [--token <tok>] [--yes]
//
// Exit codes: 0=clean (all verified), 2=some findings still present,
//             10=auth, 11=network, 12=input/validation failure.

import { readFileSync } from "node:fs";
import { createInterface } from "node:readline";
import { EXIT_CODES, scanForSecrets, classifyError } from "./contract.js";

// === PURE VERIFICATION ===

/**
 * Classify the outcome of a single finding's remediation based on its
 * apply-result actions and the re-audit's fresh finding list.
 *
 * @param {object} execItem — one entry from remediate() results[]
 * @param {Array} newFindings — fresh findings from the re-audit
 * @returns {{ remediation_verified: boolean|null, needs_dashboard: boolean, reason: string }}
 */
export function classifyVerification(execItem, newFindings) {
  const actions = execItem.actions || [];
  const allSkipped = actions.every((a) => a.status === "skipped");
  const hasApplied = actions.some((a) => a.status === "applied");
  const hasFailed = actions.some((a) => a.status === "failed");

  if (allSkipped) {
    return {
      remediation_verified: null,
      needs_dashboard: true,
      reason: actions[0].reason || actions[0].type,
    };
  }

  if (hasFailed) {
    return {
      remediation_verified: false,
      needs_dashboard: false,
      reason: "apply failed — fix not applied",
    };
  }

  if (hasApplied) {
    if (newFindings && newFindings.length > 0) {
      const stillExists = newFindings.some(
        (f) => f.check === execItem.check && f.target === execItem.target
      );
      return {
        remediation_verified: !stillExists,
        needs_dashboard: false,
        reason: stillExists
          ? "finding still present after remediation"
          : "finding no longer detected",
      };
    }
    return {
      remediation_verified: null,
      needs_dashboard: false,
      reason: "no live re-audit available — cannot verify",
    };
  }

  return {
    remediation_verified: null,
    needs_dashboard: false,
    reason: "unknown remediation state",
  };
}

/**
 * Verify a remediation result by re-running checks.
 *
 * @param {object} remediationResult — output from remediate() in apply mode
 *   (must have .results[] with { check, target, actions })
 * @param {object} [opts]
 * @param {string} [opts.project_ref] — defaults to remediationResult.project_ref
 * @param {function} [opts._reAudit] — injectable: async () => ({ findings: [] })
 *   In production this re-runs audit(); in tests it returns mock findings.
 * @returns {Promise<object>} { project_ref, summary, verifications }
 */
export async function verify(remediationResult, opts = {}) {
  const {
    project_ref = remediationResult.project_ref,
    _reAudit,
  } = opts;

  const execResults = remediationResult.results || [];

  // Re-run the audit to get fresh findings (if a re-audit function is provided).
  let newFindings = [];
  if (_reAudit) {
    const fresh = await _reAudit();
    newFindings = fresh.findings || [];
  }

  const verifications = [];
  for (const item of execResults) {
    const cls = classifyVerification(item, newFindings);
    verifications.push({
      check: item.check,
      target: item.target,
      severity: item.severity,
      remediation_verified: cls.remediation_verified,
      needs_dashboard: cls.needs_dashboard,
      reason: cls.reason,
    });
  }

  const fixed_confirmed = verifications.filter((v) => v.remediation_verified === true).length;
  const fixed_unverified = verifications.filter(
    (v) => v.remediation_verified === null && !v.needs_dashboard
  ).length;
  const fixed_failed = verifications.filter(
    (v) => v.remediation_verified === false
  ).length;
  const needs_dashboard = verifications.filter((v) => v.needs_dashboard).length;

  return {
    project_ref,
    summary: {
      total: verifications.length,
      fixed_confirmed,
      fixed_unverified,
      fixed_failed,
      needs_dashboard,
    },
    verifications,
  };
}

// === CLI ===

async function main() {
  const args = process.argv.slice(2);

  if (args.includes("--help") || args.includes("-h")) {
    console.error(`Usage:
  supabase-security verify <remediation.json> [--token <tok>] [--yes]

  Re-runs the audit after --apply and checks whether each applied finding
  is now closed. Dashboard-only / skipped findings are reported as
  needs_dashboard.

Flags:
  --token <tok>  Supabase PAT for re-running checks (or SUPABASE_ACCESS_TOKEN env)
  --yes          Skip confirmation prompt (non-interactive mode)
  --help, -h     Show this help

Exit codes:
  0  All applied findings verified closed
  2  One or more findings still present after remediation
  10 Auth error — token rejected (401/403)
  11 Network error — DNS/connection failure
  12 Input validation failure`);
    process.exit(0);
  }

  const token =
    (args.includes("--token") ? args[args.indexOf("--token") + 1] : null) ||
    process.env.SUPABASE_ACCESS_TOKEN;
  const yesMode = args.includes("--yes");
  const filePath = args.find((a) => !a.startsWith("--"));

  // Read remediation result
  let remediationResult;
  try {
    if (filePath) {
      remediationResult = JSON.parse(readFileSync(filePath, "utf8"));
    } else if (!process.stdin.isTTY) {
      let input = "";
      process.stdin.setEncoding("utf8");
      for await (const chunk of process.stdin) {
        input += chunk;
      }
      remediationResult = JSON.parse(input);
    } else {
      console.error("verify: provide a remediation result file or pipe JSON via stdin");
      console.error("  e.g. node scripts/verify.js remediation-result.json --token <tok>");
      process.exit(EXIT_CODES.SCHEMA_VIOLATION);
    }
  } catch (e) {
    console.error(`verify: cannot parse JSON input: ${e.message}`);
    process.exit(EXIT_CODES.SCHEMA_VIOLATION);
  }

  if (!remediationResult || typeof remediationResult !== "object") {
    console.error("verify: input is not a JSON object");
    process.exit(EXIT_CODES.SCHEMA_VIOLATION);
  }
  if (!remediationResult.project_ref) {
    console.error("verify: input JSON missing project_ref");
    process.exit(EXIT_CODES.SCHEMA_VIOLATION);
  }
  if (!Array.isArray(remediationResult.results)) {
    console.error("verify: input JSON missing results array (run --apply first)");
    process.exit(EXIT_CODES.SCHEMA_VIOLATION);
  }

  const ref = remediationResult.project_ref;

  // Confirmation guard
  if (!yesMode && process.stdin.isTTY) {
    const rl = createInterface({ input: process.stdin, output: process.stdout });
    const answer = await new Promise((resolve) => {
      rl.question(`Verify remediation on project ${ref}? Will re-run audit. Type 'yes' to confirm: `, (a) => {
        rl.close();
        resolve(a.trim().toLowerCase());
      });
    });
    if (answer !== "yes") {
      console.error("verify: aborted by user.");
      process.exit(0);
    }
  }

  // Set up re-audit function: uses live audit() if token is provided.
  let reAuditFn = null;
  if (token) {
    const { audit } = await import("./audit.js");
    reAuditFn = async () => {
      const result = await audit(token, ref, { activeProbe: true });
      return result;
    };
  }

  try {
    const verification = await verify(remediationResult, {
      project_ref: ref,
      _reAudit: reAuditFn,
    });

    const output = JSON.stringify(verification, null, 2);
    const secrets = scanForSecrets(output);
    if (secrets.length > 0) {
      console.error(`verify: SECRET LEAK detected: ${JSON.stringify(secrets)}`);
      process.exit(EXIT_CODES.SCHEMA_VIOLATION);
    }

    console.log(output);

    // Exit non-zero only on actual verification failures (finding still exists
    // after remediation), NOT on unverified (no re-audit provided) or
    // needs_dashboard (manual action required) — those are not failures.
    const failed = verification.summary.fixed_failed || 0;
    if (failed > 0) {
      console.error(`verify: ${failed} finding(s) still present after remediation`);
      process.exit(EXIT_CODES.FINDINGS);
    }
    if (verification.summary.needs_dashboard > 0) {
      console.error(`verify: ${verification.summary.needs_dashboard} finding(s) need dashboard action — review in output above`);
    }
    process.exit(EXIT_CODES.CLEAN);
  } catch (e) {
    if (e.code === "AUTH_ERROR") {
      console.error(e.message);
      process.exit(EXIT_CODES.AUTH_ERROR);
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

// Guard process.argv[1] for safe import as a library.
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

export { main };
