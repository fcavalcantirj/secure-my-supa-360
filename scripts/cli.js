#!/usr/bin/env node
// Subcommand CLI entry point for supabase-security.
// Dispatches: audit | probe | discover | remediate | verify | report.
// Each subcommand accepts --json and shares the finding schema (schema/finding.schema.json).
//
// Usage:
//   node scripts/cli.js audit <ref> [--json] [--html report.html] [--no-probe] [--fail-on high]
//   node scripts/cli.js probe <ref> [--json] [--no-probe] [--fail-on high]   (audit with active probe)
//   node scripts/cli.js discover [path] [--json] [--html report.html]
//   node scripts/cli.js remediate <result.json> [--apply] [--yes] [--token <tok>]
//   node scripts/cli.js verify <remediation.json> [--token <tok>] [--yes]
//   node scripts/cli.js report <file.json> [--html out.html]              (renders HTML; --json echoes input)
//   node scripts/cli.js help <subcommand>                                 (per-subcommand help)
//   node scripts/cli.js --help                                            (global help)

import { readFileSync, writeFileSync } from "node:fs";
import { main as auditMain } from "./audit.js";
import { main as remediateMain } from "./remediate.js";
import { main as verifyMain } from "./verify.js";
import { labMain } from "./lab.js";
import { renderHtml } from "./report.js";
import { EXIT_CODES } from "./contract.js";

const args = process.argv.slice(2);
const subcommand = args[0];

const SUBCOMMANDS = ["audit", "probe", "discover", "remediate", "verify", "report", "lab"];

const HELP = {
  global: `Supabase Security Auditor — subcommand CLI

Usage:
  supabase-security audit <ref> [flags]             Full audit of a Supabase project
  supabase-security probe <ref> [flags]             Active-probe audit (alias for audit; probe on by default)
  supabase-security discover [path] [flags]         Keyless static repo scan
  supabase-security remediate <result.json> [flags] Consume a prior JSON result; dry-run by default, --apply executes fixes
  supabase-security verify <remediation.json>       Re-run audit after --apply to verify fixes closed
  supabase-security report <file.json> [flags]      Render HTML from a prior JSON result (never auto-runs)
  supabase-security lab <cmd> <ref> [flags]         Lab management: seed/teardown/matrix on a disposable project
  supabase-security help <subcommand>               Show help for a specific subcommand

Env:
  SUPABASE_ACCESS_TOKEN  PAT (required for audit/probe/remediate/verify)
  SUPABASE_SERVICE_ROLE_KEY  service_role JWT (required for findings with requires_service_role=true)
  SUPA360_PERMANENT_BLOCKED_REFS  Comma-separated refs that can NEVER be remediated or used as a lab (no flag/env unblocks them). Put PRODUCTION refs here; unset by default
  SUPA360_BLOCKED_REFS  Comma-separated DISPOSABLE LAB refs — blocked unless SUPA360_LAB_REF=<same ref> + --i-understand-this-is-destructive. Never put production here; unset by default

Exit codes:
  0  Clean — no findings at/above --fail-on severity
  2  Findings — one or more findings at/above --fail-on severity
  10 Auth error — token rejected (401/403)
  11 Network error — DNS/connection failure
  12 Tool error — own output failed schema validation or secret-leak scan`,

  audit: `Usage: supabase-security audit <ref> [flags]

Full audit of a Supabase project (RLS, RPC, storage, auth, network, etc.).
Passive metadata scan by default (read-only); --probe for active confirmation.

Flags:
  --json        Output JSON to stdout (default)
  --html <path> Write HTML report to <path> instead of JSON
  --probe        Enable active anon-key probe (OPT-IN — POSTs to RPC/storage, signs up temp user). Default: OFF
  --no-probe      NO-OP alias (kept for back-compat). Active probing is OFF by default; use --probe to enable
  --fail-on <sev>  Exit 2 if findings at/above severity (critical|high|medium|low|info|never). Default: high
  --confirmed-only  Only count confirmed findings toward exit-code gate (inferred still reported). Default: off
  --baseline <path>  Write signed baseline (first run) or diff against it (subsequent runs); new findings at/above --fail-on fail the gate
  --timeout <sec>   Abort all probes + SQL after this many seconds (large-project safety). Default: 0 (no limit)
  --token <tok>   Supabase PAT (or SUPABASE_ACCESS_TOKEN env var)
  --trace         Log every Management-API query + probe to stderr (never secrets)
  --include-system-schemas  Include Supabase platform schemas (storage, realtime, auth, vault, etc.) in the scan. Default: off (excluded — vendor-controlled)

Exit codes: 0 clean / 2 findings / 10 auth / 11 network / 12 tool-error`,

  probe: `Usage: supabase-security probe <ref> [flags]

Active-probe audit (alias for 'audit' — active anon-key probe is on by default).
Use --no-probe to skip active probing.

Flags: same as 'audit'
  --json        Output JSON to stdout (default)
  --no-probe    Skip the active anon-key probe
  --fail-on <sev>  Exit 2 if findings at/above severity (critical|high|medium|low|info|never). Default: high
  --confirmed-only  Only count confirmed findings toward exit-code gate (inferred still reported). Default: off
  --baseline <path>  Write signed baseline (first run) or diff against it (subsequent runs); new findings at/above --fail-on fail the gate
  --timeout <sec>   Abort all probes + SQL after this many seconds. Default: 0 (no limit)
  --token <tok>   Supabase PAT (or SUPABASE_ACCESS_TOKEN env var)
  --trace         Log probes + queries to stderr

Exit codes: 0 clean / 2 findings / 10 auth / 11 network / 12 tool-error`,

  discover: `Usage: supabase-security discover [path] [flags]

Keyless static repo scan. Walks the repo for committed secrets + probes
anon-reachable surfaces. No PAT required.

Flags:
  --json        Output JSON to stdout (default)
  --html <path> Write HTML report to <path>

Exit codes: 0 clean / 2 findings / 12 tool-error`,

  remediate: `Usage: supabase-security remediate <result.json> [--apply] [--yes] [--token <tok>]

Consume a prior JSON audit result and produce a remediation plan.
Default is DRY-RUN (prints plan, mutates nothing). --apply executes fixes.

Flags:
  --apply          Execute fixes (SQL in BEGIN/COMMIT via Management API + mgmt API PATCH)
  --rollback        Rollback a prior --apply using its snapshot file
  --yes             Skip confirmation prompt (required with --apply/--rollback in non-TTY mode)
  --token <tok>     Supabase PAT (required for --apply/--rollback, or SUPABASE_ACCESS_TOKEN env)
  --service-role <key>  service_role JWT for findings with requires_service_role=true
  --i-understand-this-is-destructive  Acknowledge destructive action (required for lab-blocked refs; requires SUPA360_LAB_REF env matching the ref)
  --json            Output JSON to stdout (default)

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
  - Findings without rollback_sql are skipped (manual)
  - Findings with requires_service_role=true need --service-role

Exit codes: 0 success / 2 some failures / 10 auth / 11 network / 12 input-validation`,

  verify: `Usage: supabase-security verify <remediation.json> [--token <tok>] [--yes]

Re-run the audit after --apply and check whether each fixed finding is now closed.
Dashboard-only / skipped findings are reported as needs_dashboard.

Flags:
  --token <tok>  Supabase PAT for re-running checks (or SUPABASE_ACCESS_TOKEN env)
  --yes         Skip confirmation prompt (non-interactive mode)
  --json        Output JSON to stdout (default)

Exit codes: 0 all verified / 2 some findings still present / 10 auth / 11 network / 12 input-validation`,

  report: `Usage: supabase-security report <file.json> [--html out.html]

Render an HTML report from a prior JSON audit result. This is a SEPARATE step —
it never auto-runs as part of audit. Consumes the exact JSON result (no second
data path), so the report always reflects what the audit produced.

Flags:
  --html <path>   Write HTML to <path> (default: report.html)
  --json          Echo the input JSON to stdout instead of producing HTML

Exit codes: 0 success / 12 invalid input`,

  lab: `Usage: supabase-security lab <command> <ref> [flags]

Lab management for the skill's WRITE-path validation on a disposable project.

Commands:
  lab seed <ref>        Apply fixtures/seed.sql to the lab project
  lab teardown <ref>    Apply fixtures/teardown.sql (removes all seeded objects)
  lab matrix <ref>      Full end-to-end: seed -> audit -> remediate --apply -> audit -> rollback -> audit -> teardown

Flags:
  --i-understand-this-is-destructive  REQUIRED for all lab commands (they mutate a real project)
  --token <tok>    Supabase PAT (or SUPABASE_ACCESS_TOKEN env)
  --json           Output JSON to stdout (default)

Safety (WO-19c):
  Production-blocked refs require BOTH:
    env SUPA360_LAB_REF=<ref>   (must match the target ref exactly)
    --i-understand-this-is-destructive
  The env var alone never suffices; naming one blocked ref never unblocks another.

Exit codes: 0 success / 12 blocked or invalid input / 10 auth`,
};

function showHelp(cmd) {
  if (cmd && HELP[cmd]) {
    console.error(HELP[cmd]);
  } else if (cmd && !HELP[cmd]) {
    console.error(`Unknown subcommand: ${cmd}`);
    console.error(`Available: ${SUBCOMMANDS.join(", ")}`);
    process.exit(1);
  } else {
    console.error(HELP.global);
  }
  process.exit(0);
}

async function run() {
  // No subcommand, or --help/-h → global help
  if (!subcommand || subcommand === "--help" || subcommand === "-h") {
    showHelp();
  }

  // 'help <subcommand>' → per-subcommand help
  if (subcommand === "help") {
    showHelp(args[1]);
  }

  // Per-subcommand --help
  const restArgs = args.slice(1);
  if (restArgs[0] === "--help" || restArgs[0] === "-h") {
    showHelp(subcommand);
  }

  // Dispatch subcommands
  switch (subcommand) {
    case "audit":
      // Passive scan by default; user must opt-in with --probe
      process.argv = [process.argv[0], process.argv[1], ...restArgs];
      process.exit((await auditMain()) ?? 0);
      break;

    case "probe":
      // 'probe' is an alias for 'audit' with active probing ON by default.
      // Only add --probe if the user hasn't explicitly set --probe or --no-probe.
      if (!restArgs.includes("--probe") && !restArgs.includes("--no-probe")) {
        process.argv = [process.argv[0], process.argv[1], "--probe", ...restArgs];
      } else {
        process.argv = [process.argv[0], process.argv[1], ...restArgs];
      }
      process.exit((await auditMain()) ?? 0);
      break;

    case "discover":
      process.argv = [process.argv[0], process.argv[1], "--discover", ...restArgs];
      process.exit((await auditMain()) ?? 0);
      break;

    case "remediate":
      process.argv = [process.argv[0], process.argv[1], ...restArgs];
      process.exit((await remediateMain()) ?? 0);
      break;

    case "verify":
      process.argv = [process.argv[0], process.argv[1], ...restArgs];
      process.exit((await verifyMain()) ?? 0);
      break;

    case "lab":
      // Lab subcommand — seed/teardown/matrix on a disposable project.
      // Rewrites process.argv so lab.js's own main() sees the full arg list.
      process.argv = [process.argv[0], process.argv[1], ...restArgs];
      process.exit((await labMain()) ?? 0);
      break;

    case "report": {
      // Report consumes a prior JSON result and renders HTML.
      // Never auto-runs as part of audit (spec entry 2).
      const reportArgs = restArgs;
      const jsonFlag = reportArgs.includes("--json");

      let result;
      const filePath = reportArgs.find((a) => !a.startsWith("--"));
      if (filePath) {
        result = JSON.parse(readFileSync(filePath, "utf8"));
      } else if (!process.stdin.isTTY) {
        let input = "";
        process.stdin.setEncoding("utf8");
        for await (const chunk of process.stdin) input += chunk;
        result = JSON.parse(input);
      } else {
        console.error("report: provide a JSON result file or pipe via stdin");
        console.error("  e.g. node scripts/cli.js report audit-result.json --html report.html");
        process.exit(EXIT_CODES.SCHEMA_VIOLATION);
      }

      if (!result || typeof result !== "object") {
        console.error("report: input is not a JSON object");
        process.exit(EXIT_CODES.SCHEMA_VIOLATION);
      }

      if (jsonFlag) {
        // Echo input JSON (round-trip verification)
        console.log(JSON.stringify(result, null, 2));
        process.exit(0);
      }

      const htmlIdx = reportArgs.indexOf("--html");
      const out = htmlIdx !== -1 ? reportArgs[htmlIdx + 1] : "report.html";
      const html = renderHtml(result);
      writeFileSync(out, html, "utf8");
      console.error(`HTML report written to ${out}`);
      process.exit(0);
    }

    default:
      // Unknown subcommand. Handle legacy bare-ref invocations:
      // - flag-only (starts with -, e.g. `node cli.js --json`) → forward to audit
      // - bare ref (20-char alphanumeric, e.g. `node cli.js abcdefghijklmnopqrst`) → forward to audit
      if (subcommand.startsWith("-") || /^[a-z0-9]{10,30}$/.test(subcommand)) {
        process.argv = [process.argv[0], process.argv[1], ...args];
        process.exit((await auditMain()) ?? 0);
      } else {
        console.error(`Unknown subcommand: ${subcommand}`);
        console.error("Run 'supabase-security help' or 'supabase-security --help'.");
        process.exit(1);
      }
  }
}

run().catch((e) => {
  console.error(e?.message || e);
  process.exit(1);
});
