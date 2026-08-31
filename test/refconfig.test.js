// Tests for .supa360.json ref-protection config (scripts/refconfig.js).
// The load-bearing property: a malformed config must FAIL LOUD, never fail open —
// silently ignoring it would drop protection from a production project.

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { loadRefConfig, applyRefConfig } from "../scripts/refconfig.js";

function withDir(contents, fn) {
  const dir = mkdtempSync(join(tmpdir(), "supa360cfg-"));
  try {
    if (contents !== null) writeFileSync(join(dir, ".supa360.json"), contents);
    return fn(dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

function withEnv(env, fn) {
  const saved = {};
  for (const k of Object.keys(env)) {
    saved[k] = process.env[k];
    if (env[k] === undefined) delete process.env[k];
    else process.env[k] = env[k];
  }
  try { return fn(); } finally {
    for (const k of Object.keys(env)) {
      if (saved[k] === undefined) delete process.env[k];
      else process.env[k] = saved[k];
    }
  }
}

test("refconfig: missing file is not an error (config is optional)", () => {
  withDir(null, (dir) => {
    assert.deepEqual(loadRefConfig(dir), { permanent: [], lab: [] });
  });
});

test("refconfig: reads both tiers", () => {
  withDir(JSON.stringify({ permanent_blocked_refs: ["prod-a"], blocked_refs: ["lab-b"] }), (dir) => {
    const c = loadRefConfig(dir);
    assert.deepEqual(c.permanent, ["prod-a"]);
    assert.deepEqual(c.lab, ["lab-b"]);
  });
});

test("refconfig: a suppressions-only config yields no refs (back-compat)", () => {
  withDir(JSON.stringify({ suppressions: [{ target: "bucket:x", reason: "y" }] }), (dir) => {
    assert.deepEqual(loadRefConfig(dir), { permanent: [], lab: [] });
  });
});

// === fail-loud: the reason this module exists ===

test("refconfig: malformed JSON THROWS — never silently unprotects", () => {
  withDir("{ not json", (dir) => {
    assert.throws(() => loadRefConfig(dir), (e) => e.code === "CONFIG_PARSE_ERROR");
  });
});

test("refconfig: wrong type for permanent_blocked_refs THROWS", () => {
  withDir(JSON.stringify({ permanent_blocked_refs: "prod-a" }), (dir) => {
    assert.throws(() => loadRefConfig(dir), (e) => e.code === "CONFIG_PARSE_ERROR");
  });
});

test("refconfig: non-string entries THROW", () => {
  withDir(JSON.stringify({ permanent_blocked_refs: ["ok", 42] }), (dir) => {
    assert.throws(() => loadRefConfig(dir), (e) => e.code === "CONFIG_PARSE_ERROR");
  });
});

// === applyRefConfig unions with env; neither source can weaken the other ===

test("applyRefConfig: unions config with existing env, no duplicates", () => {
  withDir(JSON.stringify({ permanent_blocked_refs: ["prod-a"], blocked_refs: ["lab-b"] }), (dir) => {
    withEnv({ SUPA360_PERMANENT_BLOCKED_REFS: "prod-z,prod-a", SUPA360_BLOCKED_REFS: undefined }, () => {
      applyRefConfig(dir);
      assert.deepEqual(process.env.SUPA360_PERMANENT_BLOCKED_REFS.split(","), ["prod-z", "prod-a"]);
      assert.equal(process.env.SUPA360_BLOCKED_REFS, "lab-b");
    });
  });
});

test("applyRefConfig: config alone protects when no env var is set", () => {
  withDir(JSON.stringify({ permanent_blocked_refs: ["prod-a"] }), (dir) => {
    withEnv({ SUPA360_PERMANENT_BLOCKED_REFS: undefined }, () => {
      applyRefConfig(dir);
      assert.equal(process.env.SUPA360_PERMANENT_BLOCKED_REFS, "prod-a");
    });
  });
});
