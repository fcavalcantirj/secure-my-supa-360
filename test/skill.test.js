// Tests for spec entry 33: SKILL.md must accurately document the full check
// catalog, subcommands, exit codes, env vars, and end-to-end flow.
// The key gate: every check ID in the code must appear in SKILL.md, and the
// documented count must match.

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const ROOT = dirname(dirname(fileURLToPath(import.meta.url)));
const SKILL_PATH = join(ROOT, "SKILL.md");

// Known error identifiers in audit.js (errors.push({ check: "..." }))
// that are NOT finding checks — excluded from the catalog count.
const ERROR_IDS = new Set([
  "rls_tables", "function_secdef", "rpc_probe", "views",
  "storage_policies", "auth_config", "edge_functions",
  "network_db", "schema_grants", "default_privileges",
  "data_api", "extensions_cron", "function_body", "history",
  "postgrest_config",
]);

/** Extract all finding check IDs from the codebase (scripts/ recursively). */
function extractCheckIds() {
  const checks = new Set();
  const scriptsDir = join(ROOT, "scripts");

  function readDirRecursive(dir) {
    const results = [];
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      const fullPath = join(dir, entry.name);
      if (entry.isDirectory()) {
        results.push(...readDirRecursive(fullPath));
      } else if (entry.name.endsWith(".js")) {
        results.push(fullPath);
      }
    }
    return results;
  }

  for (const fpath of readDirRecursive(scriptsDir)) {
    const content = readFileSync(fpath, "utf8");
    // Pattern: check: "id"  (also handles check: cond ? "id" : "id")
    const checkPattern = /check:\s*(?:.*?\?\s*)?"([a-z_]+)"/g;
    let m;
    while ((m = checkPattern.exec(content)) !== null) checks.add(m[1]);
    // Pattern: secretFinding("id", ...)
    const secretPattern = /secretFinding\(\s*"([a-z_]+)"/g;
    while ((m = secretPattern.exec(content)) !== null) checks.add(m[1]);
  }

  // Extract CHECKS object keys from audit.js
  const auditContent = readFileSync(join(scriptsDir, "audit.js"), "utf8");
  let inChecks = false;
  for (const line of auditContent.split("\n")) {
    if (line.includes("const CHECKS = {")) { inChecks = true; continue; }
    if (inChecks) {
      if (line.trim() === "};") break;
      const keyMatch = line.match(/^\s{2}([a-z_]+):\s*\{/);
      if (keyMatch) checks.add(keyMatch[1]);
    }
  }

  // Remove error identifiers
  for (const id of ERROR_IDS) checks.delete(id);

  return checks;
}

function readSkill() {
  return readFileSync(SKILL_PATH, "utf8");
}

// === Check catalog completeness ===

test("SKILL.md: every check ID in code appears in SKILL.md", () => {
  const checkIds = extractCheckIds();
  const skill = readSkill();
  const missing = [...checkIds].filter((id) => !skill.includes(`\`${id}\``));
  assert.equal(
    missing.length, 0,
    `Check IDs missing from SKILL.md: ${missing.join(", ")}. Total in code: ${checkIds.size}`
  );
});

test("SKILL.md: documented check count matches code", () => {
  const checkIds = extractCheckIds();
  const skill = readSkill();
  // SKILL.md should state the total number of checks
  const countMatch = skill.match(/(\d+)\s+checks/);
  assert.ok(countMatch, "SKILL.md should state the total check count (e.g. '62 checks')");
  const documented = parseInt(countMatch[1], 10);
  assert.equal(
    documented, checkIds.size,
    `SKILL.md says ${documented} checks but code has ${checkIds.size}`
  );
});

// === Subcommands ===

test("SKILL.md: documents all subcommands", () => {
  const skill = readSkill();
  const subcommands = ["audit", "probe", "discover", "remediate", "verify", "report"];
  for (const cmd of subcommands) {
    assert.ok(
      skill.includes(cmd),
      `SKILL.md should mention subcommand '${cmd}'`
    );
  }
});

// === Flags ===

test("SKILL.md: documents key flags", () => {
  const skill = readSkill();
  const flags = ["--json", "--html", "--fail-on", "--no-probe", "--apply", "--trace"];
  for (const flag of flags) {
    assert.ok(
      skill.includes(flag),
      `SKILL.md should mention flag '${flag}'`
    );
  }
});

// === Exit codes ===

test("SKILL.md: documents all exit codes", () => {
  const skill = readSkill();
  const codes = ["0", "2", "10", "11", "12"];
  for (const code of codes) {
    assert.ok(
      skill.includes(code),
      `SKILL.md should mention exit code ${code}`
    );
  }
});

// === Env vars ===

test("SKILL.md: documents env vars", () => {
  const skill = readSkill();
  assert.ok(skill.includes("SUPABASE_ACCESS_TOKEN"), "should document SUPABASE_ACCESS_TOKEN");
  assert.ok(skill.includes("SUPABASE_DB_URL"), "should document SUPABASE_DB_URL");
});

// === Confidence classification ===

test("SKILL.md: documents confirmed vs inferred confidence", () => {
  const skill = readSkill();
  assert.ok(skill.includes("confirmed"), "should mention confirmed confidence");
  assert.ok(skill.includes("inferred"), "should mention inferred confidence");
});

// === End-to-end flow ===

test("SKILL.md: documents end-to-end agent flow", () => {
  const skill = readSkill();
  assert.ok(
    skill.includes("audit") && skill.includes("remediate") && skill.includes("verify"),
    "should document audit -> remediate -> verify flow"
  );
});

// === Trust / secret handling ===

test("SKILL.md: documents secret/token handling", () => {
  const skill = readSkill();
  assert.ok(
    skill.includes("never") && (skill.includes("persist") || skill.includes("persisted") || skill.includes("stored") || skill.toLowerCase().includes("local")),
    "should mention that tokens are never persisted"
  );
  assert.ok(
    skill.toLowerCase().includes("secret"),
    "should mention secret handling"
  );
});
