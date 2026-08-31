// Ref-protection config loader (.supa360.json).
//
// Lets an operator declare protected project refs in a file instead of remembering
// to export env vars on every invocation. The file is a convenience layer over the
// SAME two tiers documented in remediate.js — it does not add a third mechanism:
//
//   { "permanent_blocked_refs": ["my-prod-ref"],   // tier 1 — NEVER unblockable
//     "blocked_refs":           ["my-lab-ref"] }   // tier 2 — unblockable via ceremony
//
// Values are UNIONed with SUPA360_PERMANENT_BLOCKED_REFS / SUPA360_BLOCKED_REFS.
// A ref protected by either source is protected; neither can weaken the other.
//
// DELIBERATE: unlike loadSuppressions(), a malformed file is a HARD ERROR. A
// suppression list that fails to parse merely reports more findings; a blocklist
// that fails to parse would silently remove protection from a production project.
// Fail loud, never fail open.
//
// NOTE: .supa360.json may name real project refs, so it is gitignored. Never commit it.

import { readFileSync } from "node:fs";

const CONFIG_FILE = ".supa360.json";

/** Read declared refs from .supa360.json. Returns { permanent: [], lab: [] }.
 *  Missing file → empty (not an error: the file is optional).
 *  Malformed file or wrong types → throws. */
export function loadRefConfig(dir) {
  const cwd = dir || process.cwd();
  const path = `${cwd}/${CONFIG_FILE}`;
  let raw;
  try {
    raw = readFileSync(path, "utf8");
  } catch {
    return { permanent: [], lab: [] };
  }

  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch (e) {
    const err = new Error(
      `${CONFIG_FILE} is present but not valid JSON (${e.message}). ` +
      `Refusing to continue: this file can declare protected production refs, and ` +
      `ignoring it would silently drop that protection.`
    );
    err.code = "CONFIG_PARSE_ERROR";
    throw err;
  }

  const readList = (key) => {
    const v = parsed[key];
    if (v === undefined || v === null) return [];
    if (!Array.isArray(v) || v.some((x) => typeof x !== "string")) {
      const err = new Error(`${CONFIG_FILE}: "${key}" must be an array of strings.`);
      err.code = "CONFIG_PARSE_ERROR";
      throw err;
    }
    return v.map((x) => x.trim()).filter(Boolean);
  };

  return { permanent: readList("permanent_blocked_refs"), lab: readList("blocked_refs") };
}

/** Merge .supa360.json refs INTO the env vars the guard reads, so config and env
 *  are additive and the guard itself stays free of file I/O.
 *  Call once at CLI startup, before any guard check. */
export function applyRefConfig(dir) {
  const { permanent, lab } = loadRefConfig(dir);
  const merge = (name, extra) => {
    if (!extra.length) return;
    const existing = (process.env[name] || "").split(",").map((s) => s.trim()).filter(Boolean);
    process.env[name] = [...new Set([...existing, ...extra])].join(",");
  };
  merge("SUPA360_PERMANENT_BLOCKED_REFS", permanent);
  merge("SUPA360_BLOCKED_REFS", lab);
  return { permanent: permanent.length, lab: lab.length };
}
