// WO-4(b): Lint every emitted CREATE POLICY statement for Supabase guidance compliance.
// Rule #6 from the Supabase RLS guide is the only rule that closes a hole:
// "Use TO authenticated (omit => PUBLIC includes anon)."
//
// Asserts:
//  (1) FIX SQL CREATE POLICY: must have explicit TO authenticated (never PUBLIC, never omitted)
//  (2) auth.uid() in FIX SQL predicates is wrapped as (select auth.uid())
//  (3) No JOIN or correlated subquery in FIX SQL predicates
//
// Rollback SQL may restore TO public (it's restoring the ORIGINAL state,
// which is the divergence we're flagging — not silently rewriting).

import { test } from "node:test";
import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const CHECKS_DIR = join(__dirname, "..", "scripts", "checks");

import { classifyTable } from "../scripts/checks/rls.js";
import { classifyPolicyPerf, classifyPublicRolePolicy } from "../scripts/checks/rls_perf.js";
import { processRealtime } from "../scripts/checks/realtime.js";

// Helper: extract fix.sql and rollback_sql arrays from a finding
function extractSql(f) {
  return {
    fix: f?.fix?.sql || [],
    rollback: f?.fix?.rollback_sql || [],
  };
}

// Collect all SQL strings
const FIX_SQL = [];
const ROLLBACK_SQL = [];
const DIVERGENCE_NOTES = [];

function collect(f) {
  const { fix, rollback } = extractSql(f);
  FIX_SQL.push(...fix);
  ROLLBACK_SQL.push(...rollback);
}

// --- rls.js: permissive read policy (emits CREATE POLICY TO authenticated) ---
const rlsPermRead = classifyTable({
  schema_name: "public", table_name: "leaky",
  rls_enabled: true, policies: [{ policyname: "leak", cmd: "ALL", roles: ["public"], qual: "true", with_check: "true" }],
  anon_select: true, auth_select: true, columns: [],
}, null);
if (rlsPermRead) collect(rlsPermRead);

// rls.js: permissive write policy (FOR INSERT — the previously-divergent one)
const rlsPermWrite = classifyTable({
  schema_name: "public", table_name: "leaky",
  rls_enabled: true, policies: [{ policyname: "leak_w", cmd: "INSERT", roles: ["public"], qual: "true", with_check: "true" }],
  anon_insert: true, columns: [],
}, null);
if (rlsPermWrite) collect(rlsPermWrite);

// --- rls_perf.js: unwrapped auth function (wraps auth.uid()) ---
const uaf = classifyPolicyPerf({
  policyname: "p", cmd: "SELECT", roles: ["authenticated"],
  qual: "auth.uid() = user_id", with_check: "true",
}, "mytable");
if (uaf) collect(uaf);

// --- rls_perf.js: public-role policy (fix=TO authenticated, rollback=TO public) ---
const prp = classifyPublicRolePolicy({
  policyname: "p", cmd: "ALL", roles: ["public"],
  qual: "true", with_check: "true",
}, "mytable");
if (prp) {
  collect(prp);
  // The rollback restores TO public — this is a known divergence from guidance.
  // We flag it for review, not silently rewrite it.
  const rollbackSql = (prp.fix?.rollback_sql || []).find((s) => /CREATE POLICY/i.test(s));
  if (rollbackSql && /\bTO\s+public\b/i.test(rollbackSql)) {
    DIVERGENCE_NOTES.push(`rollback restores original TO public: ${rollbackSql.trim()}`);
  }
}

// --- realtime.js: anon read/write policies ---
const rtFindings = await processRealtime(
  {
    realtimeTables: [],
    realtimeMessages: {
      rls_enabled: true, anon_select: true, auth_select: true,
      anon_insert: true, auth_insert: true, anon_delete: true, has_policies: false,
    },
  },
  "test-ref",
  null
);
for (const f of (rtFindings || [])) collect(f);

// Extract CREATE POLICY strings from FIX SQL only
const FIX_CREATE_POLICIES = FIX_SQL.filter((s) =>
  typeof s === "string" && /\bCREATE\s+POLICY\b/i.test(s)
);

test("WO-4(b) lint: corpus has CREATE POLICY fix SQL", () => {
  assert.ok(FIX_CREATE_POLICIES.length > 0, "should have CREATE POLICY fix SQL");
});

test("WO-4(b) lint (FIX SQL): every CREATE POLICY has explicit TO authenticated", () => {
  for (const sql of FIX_CREATE_POLICIES) {
    assert.ok(/\bTO\s+/i.test(sql), `missing TO clause: ${sql}`);
    assert.ok(/\bTO\s+authenticated\b/i.test(sql), `should use TO authenticated: ${sql}`);
    assert.ok(!/\bTO\s+public\b/i.test(sql), `uses TO PUBLIC in FIX (includes anon, rule #6): ${sql}`);
  }
});

test("WO-4(b) lint (FIX SQL): auth.uid() wrapped as (select auth.uid())", () => {
  for (const sql of FIX_CREATE_POLICIES) {
    if (/auth\.uid\(\)/i.test(sql)) {
      assert.ok(
        /\(\s*select\s+auth\.uid\(\s*\)\s*\)/i.test(sql),
        `auth.uid() not wrapped: ${sql}`
      );
    }
  }
});

test("WO-4(b) lint (FIX SQL): no JOIN or correlated subquery in CREATE POLICY", () => {
  for (const sql of FIX_CREATE_POLICIES) {
    assert.ok(!/\bJOIN\b/i.test(sql), `JOIN in CREATE POLICY: ${sql}`);
    assert.ok(!/\bIN\s*\(\s*SELECT\b/i.test(sql), `correlated IN (SELECT) in CREATE POLICY: ${sql}`);
  }
});

test("WO-4(b) lint: previously-divergent policies fixed", () => {
  // realtime read policy
  const rtSql = FIX_CREATE_POLICIES.find((s) => s.includes("authenticated read"));
  assert.ok(rtSql, "realtime read policy should exist in FIX SQL");
  assert.ok(/\bTO\s+authenticated\b/i.test(rtSql), `missing TO authenticated: ${rtSql}`);

  // write policy (FOR INSERT)
  const writeSql = FIX_CREATE_POLICIES.find((s) => /FOR\s+INSERT/i.test(s) && /owner_write/i.test(s));
  assert.ok(writeSql, "write policy should exist in FIX SQL");
  assert.ok(/\bTO\s+authenticated\b/i.test(writeSql), `missing TO authenticated: ${writeSql}`);
});

test("WO-4(b) lint: rollback divergences are surfaced, not hidden", () => {
  // The public-role policy rollback restores TO public — this is the original
  // (divergent) state. We surface it as a divergence note, not silently rewrite.
  assert.ok(DIVERGENCE_NOTES.length > 0, "should have at least one divergence note for rollback");
  for (const note of DIVERGENCE_NOTES) {
    assert.ok(note.includes("TO public"), `divergence note mentions TO public: ${note}`);
  }
});

// WO-19: no merged grantees in any rollback_sql GRANT (WO-5 prevention).
// Merged grantees (TO role1, role2) in rollback restore privileges to roles
// that never had them — the WO-5 class of bug. Static scan of all check modules.
test("WO-19: no merged grantees in rollback_sql GRANT (WO-5 prevention)", () => {
  const files = readdirSync(CHECKS_DIR).filter((f) => f.endsWith(".js"));
  const mergedPattern = /\bGRANT\b.*\bTO\b\s+\w+\s*,\s*\w+/i;
  const violations = [];

  for (const file of files) {
    const content = readFileSync(join(CHECKS_DIR, file), "utf8");
    const lines = content.split("\n");
    for (let i = 0; i < lines.length; i++) {
      if (lines[i].includes("rollback_sql") || (i > 0 && lines[i - 1].includes("rollback_sql"))) {
        if (mergedPattern.test(lines[i])) {
          violations.push(`${file}:${i + 1}: ${lines[i].trim()}`);
        }
      }
    }
  }

  assert.equal(violations.length, 0,
    `rollback_sql must not have merged grantees:\n${violations.join("\n")}`);
});

// WO-5: no hardcoded multi-privilege GRANT lists in any check module source.
// A single GRANT listing multiple privileges (GRANT SELECT, INSERT, ...) is the
// exact pattern that caused the original bug: rollback grants write privileges
// the role never held. Runtime-generated rollback_sql_exact (from state.js
// generateRollbackFromState) is exempt — it is not in source files.
// This scan enforces that source files in scripts/checks/ contain zero matches.
test("WO-5: no hardcoded multi-privilege GRANT in scripts/checks/ (regression)", () => {
  const files = readdirSync(CHECKS_DIR).filter((f) => f.endsWith(".js"));
  const multiPrivGrantPattern = /GRANT\s+(SELECT|INSERT|UPDATE|DELETE|USAGE)\s*,/i;
  const violations = [];

  for (const file of files) {
    const content = readFileSync(join(CHECKS_DIR, file), "utf8");
    const lines = content.split("\n");
    for (let i = 0; i < lines.length; i++) {
      if (multiPrivGrantPattern.test(lines[i])) {
        violations.push(`${file}:${i + 1}: ${lines[i].trim()}`);
      }
    }
  }

  assert.equal(violations.length, 0,
    `rollback SQL must not contain hardcoded multi-privilege GRANTs:\n${violations.join("\n")}`);
});

// === no placeholder value may ever be sent to a live project (2026-08-31) ===
// auth.js PATCHed { security_captcha_secret: "<your_secret>" } into the customer's
// live auth config and enabled captcha with it — breaking sign-up — while its
// rollback restored only the `enabled` flag. A fix requiring a value only the
// operator has is a dashboard action, not an auto-fix.

test("no check emits an angle-bracket placeholder in executable fix content", () => {
  const files = readdirSync(CHECKS_DIR).filter((f) => f.endsWith(".js"));
  const placeholder = /"<[a-z_][a-z0-9_]*>"/i;
  const violations = [];
  for (const file of files) {
    const lines = readFileSync(join(CHECKS_DIR, file), "utf8").split("\n");
    lines.forEach((line, i) => {
      if (!placeholder.test(line)) return;
      // A placeholder inside a comment or a dashboard_action string is guidance for a
      // human and is fine. Anything else would be sent to the project.
      const t = line.trim();
      if (t.startsWith("//") || t.startsWith("--") || t.includes("dashboard_action")) return;
      violations.push(`${file}:${i + 1}: ${t}`);
    });
  }
  assert.equal(violations.length, 0,
    `placeholder values must never reach a live project:\n${violations.join("\n")}`);
});
