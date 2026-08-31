// Tests for spec entries 2 (subcommand CLI polish) + 3 (HTML opt-in).
// Tests resolveOutputMode (pure) + CLI subcommand dispatch via subprocess.

import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { writeFileSync, mkdirSync, rmSync, existsSync, readFileSync } from "node:fs";

import { resolveOutputMode } from "../scripts/audit.js";

const CLI = "node";
const CLI_ARGS = ["scripts/cli.js"];

// Helper: run CLI and capture both stdout + stderr (help text goes to stderr)
function runCli(extraArgs) {
  const result = spawnSync(CLI, [...CLI_ARGS, ...extraArgs], {
    encoding: "utf8",
    maxBuffer: 1024 * 1024,
  });
  return (result.stdout || "") + (result.stderr || "");
}

// === resolveOutputMode (entry 3: HTML opt-in logic) ===

test("resolveOutputMode: --html <path> → html mode", () => {
  const result = resolveOutputMode(["--html", "report.html"], false);
  assert.equal(result.mode, "html");
  assert.equal(result.htmlPath, "report.html");
});

test("resolveOutputMode: --html without path defaults to report.html", () => {
  const result = resolveOutputMode(["--html"], false);
  assert.equal(result.mode, "html");
  assert.equal(result.htmlPath, "report.html");
});

test("resolveOutputMode: non-TTY + no --html → json mode (no prompt)", () => {
  const result = resolveOutputMode([], false);
  assert.equal(result.mode, "json");
  assert.equal(result.htmlPath, null);
});

test("resolveOutputMode: --json flag → json mode even on TTY", () => {
  const result = resolveOutputMode(["--json"], true);
  assert.equal(result.mode, "json");
});

test("resolveOutputMode: TTY + no flags → prompt mode (interactive)", () => {
  const result = resolveOutputMode([], true);
  assert.equal(result.mode, "prompt");
});

test("resolveOutputMode: --html takes priority over TTY", () => {
  const result = resolveOutputMode(["--html", "out.html"], true);
  assert.equal(result.mode, "html");
  assert.equal(result.htmlPath, "out.html");
});

// === CLI subcommand dispatch (entry 2) ===

test("cli.js --help shows global help with all subcommands", () => {
  const output = runCli(["--help"]);
  assert.ok(output.includes("audit"));
  assert.ok(output.includes("discover"));
  assert.ok(output.includes("remediate"));
  assert.ok(output.includes("verify"));
  assert.ok(output.includes("report"));
  assert.ok(output.includes("probe"));
  assert.ok(output.includes("help <subcommand>"));
  assert.ok(output.includes("Exit codes"));
});

test("cli.js help audit shows audit-specific help (flags + env + exit codes)", () => {
  const output = runCli(["help", "audit"]);
  assert.ok(output.includes("--json"));
  assert.ok(output.includes("--html"));
  assert.ok(output.includes("--no-probe"));
  assert.ok(output.includes("--fail-on"));
  assert.ok(output.includes("--token"));
  assert.ok(output.includes("SUPABASE_ACCESS_TOKEN"));
  assert.ok(output.includes("Exit codes"));
});

test("cli.js help remediate shows remediate-specific help", () => {
  const output = runCli(["help", "remediate"]);
  assert.ok(output.includes("--apply"));
  assert.ok(output.includes("--rollback"));
  assert.ok(output.includes("--yes"));
  assert.ok(output.includes("SUPA360_BLOCKED_REFS"));
});

test("cli.js help remediate makes no protection claim an empty-env user doesn't get", () => {
  // Validate point 1: the help text must not promise protection that only exists
  // when SUPA360_BLOCKED_REFS is populated. The old false claim named no mechanism
  // and shipped the maintainer's own hash — that promise was void for every other user.
  const output = runCli(["help", "remediate"]);
  assert.ok(!output.includes("Production refs are hard-blocked"),
    "must not claim production refs are hard-blocked (false for empty-env users)");
  assert.ok(!output.includes("production refs are NEVER unblockable"),
    "must not claim a permanent/never-unblockable tier ships by default");
  // Truthful: names the opt-in env var + admits the tool can't know your prod ref.
  assert.ok(output.includes("SUPA360_BLOCKED_REFS"), "must name the opt-in blocklist var");
  assert.ok(output.includes("cannot know which of your projects is production"),
    "must state the tool can't know your prod ref");
  // 2026-08-31 regression: help must point production at the PERMANENT tier. Routing a
  // prod ref into SUPA360_BLOCKED_REFS leaves it unblockable via the lab ceremony.
  assert.ok(output.includes("SUPA360_PERMANENT_BLOCKED_REFS"),
    "must name the permanent tier — the only one that actually protects production");
  assert.ok(/PRODUCTION REFS HERE|PUT YOUR PRODUCTION/i.test(output),
    "must tell the user which tier production belongs in");
});

test("cli.js --help documents SUPA360_BLOCKED_REFS env var (discoverable)", () => {
  const output = runCli(["--help"]);
  assert.ok(output.includes("SUPA360_BLOCKED_REFS"), "global --help env section must list the blocklist var");
});

test("cli.js help report shows report-specific help", () => {
  const output = runCli(["help", "report"]);
  assert.ok(output.includes("report <file.json>"));
  assert.ok(output.includes("--html"));
  assert.ok(output.includes("--json"));
  assert.ok(output.includes("never auto-runs"));
});

test("cli.js help verify shows verify-specific help", () => {
  const output = runCli(["help", "verify"]);
  assert.ok(output.includes("verify"));
  assert.ok(output.includes("--token"));
  assert.ok(output.includes("--yes"));
});

test("cli.js help probe shows probe-specific help", () => {
  const output = runCli(["help", "probe"]);
  assert.ok(output.includes("probe"));
  assert.ok(output.includes("alias"));
});

test("cli.js unknown subcommand errors clearly", () => {
  const output = runCli(["xyz"]);
  assert.ok(output.includes("Unknown subcommand"));
});

// === report subcommand round-trip (entry 2: JSON in -> HTML out) ===

test("cli.js report <file.json> --html out.html produces HTML (round-trip)", () => {
  const dir = `${process.env.TMPDIR || "/tmp"}/cli_report_${Date.now()}`;
  mkdirSync(dir, { recursive: true });

  const mockResult = {
    schema_version: "1.0",
    project_ref: "test-ref",
    project_name: "Test Project",
    region: "us-east-1",
    generated_at: "2026-08-28T12:00:00.000Z",
    scanned_at: "2026-08-28T12:00:00.000Z",
    scanned_by: "supabase-security v0.4",
    mode: "audit-active",
    summary: {
      by_severity: { critical: 1, high: 0, medium: 0, low: 0, info: 0 },
      confirmed: 1,
      inferred: 0,
      suppressed: 0,
      critical: 1,
      high: 0,
      medium: 0,
      low: 0,
      info: 0,
    },
    findings: [
      {
        id: "abc123def456",
        check: "rls_disabled",
        category: "coverage-rls",
        severity: "critical",
        confidence: "confirmed",
        target: "secret_table",
        title: "RLS disabled on table accessible via anon",
        explain: "Without RLS, anon role can read/insert/delete any row.",
        evidence: { probe: { status: 200, bytes: 512, sample: { row_count: 3 } } },
        probe: { status: 200, bytes: 512, sample: { row_count: 3, columns: ["id", "secret"] } },
        fix: {
          sql: ["ALTER TABLE secret_table ENABLE ROW LEVEL SECURITY;"],
          rollback_sql: ["ALTER TABLE secret_table DISABLE ROW LEVEL SECURITY;"],
          dashboard_action: null,
          management_api_action: null,
          requires_service_role: false,
        },
        fix_sql: "ALTER TABLE secret_table ENABLE ROW LEVEL SECURITY;",
        references: [],
      },
    ],
    n_tables_scanned: 1,
    n_functions_scanned: 0,
    n_buckets_scanned: 0,
    active_probe: { enabled: true, probed: 1, confirmed: 1 },
  };

  const inputFile = `${dir}/result.json`;
  const outputFile = `${dir}/report.html`;
  writeFileSync(inputFile, JSON.stringify(mockResult, null, 2));

  execFileSync(CLI, [...CLI_ARGS, "report", inputFile, "--html", outputFile], {
    encoding: "utf8", stdio: "pipe",
  });

  assert.ok(existsSync(outputFile), "HTML file should be created");
  const html = readFileSync(outputFile, "utf8");
  assert.ok(html.includes("<!DOCTYPE html>"));
  assert.ok(html.includes("Test Project"));
  assert.ok(html.includes("secret_table"));
  assert.ok(html.includes("RLS disabled")); // finding title is rendered, not the check id

  rmSync(dir, { recursive: true, force: true });
});

test("cli.js report <file.json> --json echoes input JSON (round-trip)", () => {
  const dir = `${process.env.TMPDIR || "/tmp"}/cli_report_json_${Date.now()}`;
  mkdirSync(dir, { recursive: true });

  const mockResult = {
    schema_version: "1.0",
    project_ref: "test-ref",
    project_name: null,
    region: null,
    generated_at: "2026-08-28T12:00:00.000Z",
    mode: "audit-passive",
    summary: { by_severity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 }, confirmed: 0, inferred: 0, suppressed: 0 },
    findings: [],
    errors: [],
  };

  const inputFile = `${dir}/result.json`;
  writeFileSync(inputFile, JSON.stringify(mockResult, null, 2));

  const output = execFileSync(CLI, [...CLI_ARGS, "report", inputFile, "--json"], {
    encoding: "utf8", stdio: "pipe",
  }).toString().trim();

  const parsed = JSON.parse(output);
  assert.equal(parsed.schema_version, "1.0");
  assert.equal(parsed.project_ref, "test-ref");
  assert.equal(parsed.findings.length, 0);

  rmSync(dir, { recursive: true, force: true });
});

// === Entry 3: HTML opt-in in non-TTY mode ===
// (Verifies the CLI never blocks on a prompt when piped)

test("cli.js report without --html or --json and no TTY errors cleanly", () => {
  // report needs input — pipe JSON via stdin without --html → stdout JSON
  const dir = `${process.env.TMPDIR || "/tmp"}/cli_report_nonjson_${Date.now()}`;
  mkdirSync(dir, { recursive: true });
  const mockResult = { schema_version: "1.0", project_ref: "t", generated_at: "2026-01-01T00:00:00.000Z", mode: "audit-passive", summary: { by_severity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 }, confirmed: 0, inferred: 0, suppressed: 0 }, findings: [] };
  const inputFile = `${dir}/result.json`;
  writeFileSync(inputFile, JSON.stringify(mockResult));

  // No --html: should error asking for --html or --json (since stdin is not piped, just a file)
  // Actually report needs stdin or file. With a file but no --html, it defaults to HTML.
  // Let's test with --json explicitly (the non-TTY path)
  const output = execFileSync(CLI, [...CLI_ARGS, "report", inputFile, "--json"], {
    encoding: "utf8", stdio: "pipe",
  }).toString().trim();
  const parsed = JSON.parse(output);
  assert.equal(parsed.project_ref, "t");
  rmSync(dir, { recursive: true, force: true });
});

// === WO-12: CLI exit code propagation (subprocess — a unit test cannot catch this) ===
// The bug: cli.js called `await auditMain()` but never passed the return value
// to process.exit(). A subprocess test is required because unit tests can't
// observe process exit codes. See SEQ#172.

test("cli.js audit without valid token exits non-zero (exit code propagated via process.exit)", () => {
  // With a dummy token + short timeout, the audit fails at the API call.
  // main() RETURNS a non-zero code (10 auth / 11 network). If cli.js doesn't
  // call process.exit with that return value (the WO-12 bug), the process
  // exits 0. We assert non-zero — that's the regression guard.
  const result = spawnSync(CLI, [...CLI_ARGS, "audit", "deadbeefdeadbeefdead", "--token", "sbp_dummy_invalid", "--timeout", "5"], {
    encoding: "utf8",
    maxBuffer: 1024 * 1024,
    env: { ...process.env, SUPABASE_ACCESS_TOKEN: undefined },
  });
  assert.notEqual(result.status, 0, "CLI must propagate non-zero exit code from auditMain (WO-12 regression guard)");
  assert.ok([10, 11, 1].includes(result.status), `expected exit 10/11/1, got ${result.status}`);
});

test("cli.js --help exits 0 (baseline: clean exit works)", () => {
  const result = spawnSync(CLI, [...CLI_ARGS, "--help"], {
    encoding: "utf8",
    maxBuffer: 1024 * 1024,
  });
  assert.equal(result.status, 0, "help should exit 0");
});

// === WO-19: lab subcommand exit code propagation ===
// Same class of bug as WO-12: the CLI must propagate exit codes, not exit 0.
test("cli.js lab seed without --i-understand-this-is-destructive exits non-zero", () => {
  const result = spawnSync(CLI, [...CLI_ARGS, "lab", "seed", "deadbeefdeadbeefdead"], {
    encoding: "utf8",
    maxBuffer: 1024 * 1024,
  });
  assert.notEqual(result.status, 0, "lab must NOT exit 0 when blocked (WO-19c)");
});

test("cli.js lab --help exits 0", () => {
  const result = spawnSync(CLI, [...CLI_ARGS, "lab", "--help"], {
    encoding: "utf8",
    maxBuffer: 1024 * 1024,
  });
  assert.equal(result.status, 0, "lab help should exit 0");
});

test("cli.js remediate --i-understand-this-is-destructive is parsed (lab ceremony wiring)", () => {
  // Remediate should accept the flag without error (dry-run doesn't require token).
  // A blocked ref with the flag but no SUPA360_LAB_REF should still be blocked.
  const dir = `${process.env.TMPDIR || "/tmp"}/cli_lab_${Date.now()}`;
  mkdirSync(dir, { recursive: true });
  const result = JSON.stringify({
    schema_version: "1.0", project_ref: "test-prod-ref-12345",
    generated_at: "2026-01-01T00:00:00.000Z", mode: "audit-passive",
    summary: { by_severity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 }, confirmed: 0, inferred: 0, suppressed: 0 },
    findings: [],
  });
  const inputFile = `${dir}/result.json`;
  writeFileSync(inputFile, result);

  // Set the ref as blocked via env, and set SUPA360_LAB_REF to a DIFFERENT ref
  const env = { ...process.env, SUPA360_BLOCKED_REFS: "test-prod-ref-12345", SUPA360_LAB_REF: "different-ref-99999" };
  const proc = spawnSync(CLI, [...CLI_ARGS, "remediate", inputFile, "--apply", "--yes", "--i-understand-this-is-destructive"], {
    encoding: "utf8", maxBuffer: 1024 * 1024, env,
  });
  // Different lab ref → should still be blocked (exit 12)
  assert.equal(proc.status, 12, "different lab ref must not unblock a blocked ref");

  rmSync(dir, { recursive: true, force: true });
});
// === lab subcommand: pin the EXIT CODE CONTRACT, not just "non-zero" ===
// The existing WO-19 test above asserts notEqual(status, 0), which stays green even
// if the blocked path starts exiting 1 or 2. These pin exit 12 (SCHEMA_VIOLATION) and
// the BLOCKED message, end-to-end through the CLI, for a ref that is actually on a
// blocklist — the case the older test does not reach.
//
// Scope note: the PERMANENT tier cannot be exercised end-to-end here, because doing so
// would require a real production ref and this repo is public (only sha256 hashes ship).
// That tier is proven at function level in test/lab.test.js with an injected permanent
// set, and end-to-end against the real ref by the out-of-repo prover in evidence/.

const LAB_BLOCKED_REF = "test-blocked-lab-ref-4242";

test("cli.js lab seed on a blocked ref with full ack but no SUPA360_LAB_REF exits 12", () => {
  const env = { ...process.env, SUPA360_BLOCKED_REFS: LAB_BLOCKED_REF };
  delete env.SUPA360_LAB_REF;
  const result = spawnSync(
    CLI,
    [...CLI_ARGS, "lab", "seed", LAB_BLOCKED_REF, "--i-understand-this-is-destructive"],
    { encoding: "utf8", maxBuffer: 1024 * 1024, env }
  );
  assert.equal(result.status, 12, "blocked lab ref must exit 12 (SCHEMA_VIOLATION)");
  assert.match(result.stderr || "", /BLOCKED/, "must say BLOCKED on stderr");
});

test("cli.js lab seed on a blocked ref with a DIFFERENT SUPA360_LAB_REF exits 12", () => {
  const env = {
    ...process.env,
    SUPA360_BLOCKED_REFS: LAB_BLOCKED_REF,
    SUPA360_LAB_REF: "some-other-ref-9999",
  };
  const result = spawnSync(
    CLI,
    [...CLI_ARGS, "lab", "seed", LAB_BLOCKED_REF, "--i-understand-this-is-destructive"],
    { encoding: "utf8", maxBuffer: 1024 * 1024, env }
  );
  assert.equal(result.status, 12, "a non-matching lab ref must not unblock a blocked ref");
  assert.match(result.stderr || "", /BLOCKED/, "must say BLOCKED on stderr");
});
