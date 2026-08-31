// Tests for lab ref allowlist safety (WO-19c: two-tier blocklist).
// Critical: a permanent prod ref must NEVER be unblocked, even when the
// lab env var names that exact ref and both flags are passed.

import { test } from "node:test";
import assert from "node:assert/strict";

import {
  checkLabRef,
} from "../scripts/lab.js";
import {
  isBlockedRef,
  refHash,
  remediate,
  rollbackRemediation,
  PERMANENT_BLOCKED_REF_HASHES,
  LAB_ELIGIBLE_REF_HASHES,
} from "../scripts/remediate.js";

const DUMMY_LAB = "test-lab-ref-99999";
const DUMMY_OTHER = "test-other-ref-88888";
const DUMMY_PERM = "test-perm-ref-77777";

// Compute test-only hash sets (never using real prod ref strings)
const testPermSet = new Set([refHash(DUMMY_PERM)]);
const testLabSet = new Set();

// Helper: save/restore env
function withEnv(env, fn) {
  const saved = {};
  for (const k of Object.keys(env)) {
    saved[k] = process.env[k];
    if (env[k] === undefined) delete process.env[k];
    else process.env[k] = env[k];
  }
  try {
    return fn();
  } finally {
    for (const k of Object.keys(env)) {
      if (saved[k] === undefined) delete process.env[k];
      else process.env[k] = saved[k];
    }
  }
}

// === (a) permanent prod ref + lab env naming itself + both flags → STILL BLOCKED ===

test("WO-19c (a): permanent ref + SUPA360_LAB_REF=<same> + both flags → PROD_REF_BLOCKED", () => {
  withEnv({}, () => {
    // DUMMY_PERM is in the test permanent set; lab ceremony must NOT unblock it
    const blocked = isBlockedRef(DUMMY_PERM, { allowLab: true, destructiveAck: true }, testPermSet, testLabSet);
    assert.equal(blocked, true, "permanent ref must never be unblocked, even with full lab ceremony");
  });
});

// === (b) permanent prod ref + every combination → always blocked ===

test("WO-19c (b): permanent ref survives all env/flag combinations", () => {
  const combos = [
    { LAB_REF: undefined, ack: false },
    { LAB_REF: undefined, ack: true },
    { LAB_REF: DUMMY_PERM, ack: false },
    { LAB_REF: DUMMY_PERM, ack: true },
    // Validate: SUPA360_LAB_REF naming a DIFFERENT ref must not unblock a permanent ref.
    { LAB_REF: DUMMY_OTHER, ack: true },
  ];
  for (const c of combos) {
    withEnv({ SUPA360_LAB_REF: c.LAB_REF }, () => {
      const blocked = isBlockedRef(DUMMY_PERM, { allowLab: c.ack, destructiveAck: c.ack }, testPermSet, testLabSet);
      assert.equal(blocked, true, `perm ref must be blocked for LAB_REF=${c.LAB_REF}, ack=${c.ack}`);
    });
  }
});

// === (c) same combinations through the lab-eligible tier ===

test("WO-19c (c): lab-eligible ref + full ceremony → allowed", () => {
  withEnv({ SUPA360_LAB_REF: DUMMY_LAB, SUPA360_BLOCKED_REFS: DUMMY_LAB }, () => {
    const blocked = isBlockedRef(DUMMY_LAB, { allowLab: true, destructiveAck: true });
    assert.equal(blocked, false, "lab-eligible ref + ceremony → unblocked");
  });
});

test("WO-19c (c-1): lab-eligible ref, env only (no ack) → blocked", () => {
  withEnv({ SUPA360_LAB_REF: DUMMY_LAB, SUPA360_BLOCKED_REFS: DUMMY_LAB }, () => {
    const blocked = isBlockedRef(DUMMY_LAB, { allowLab: false, destructiveAck: false });
    assert.equal(blocked, true, "env var alone must not suffice");
  });
});

test("WO-19c (c-2): lab-eligible ref, ack only (no env) → blocked", () => {
  withEnv({ SUPA360_BLOCKED_REFS: DUMMY_LAB }, () => {
    delete process.env.SUPA360_LAB_REF;
    const blocked = isBlockedRef(DUMMY_LAB, { allowLab: true, destructiveAck: true });
    assert.equal(blocked, true, "ack flag alone must not suffice");
  });
});

// === (d) naming one blocked ref must NOT unblock a different one ===

test("WO-19c (d): lab env names DUMMY_LAB, target DUMMY_OTHER → still blocked", () => {
  withEnv({ SUPA360_LAB_REF: DUMMY_LAB, SUPA360_BLOCKED_REFS: `${DUMMY_LAB},${DUMMY_OTHER}` }, () => {
    const blocked = isBlockedRef(DUMMY_OTHER, { allowLab: true, destructiveAck: true });
    assert.equal(blocked, true, "naming one blocked ref must not unblock a different one");
  });
});

// === (e) no project hashes ship in the binary ===

test("WO-19c (e): shipped PERMANENT/LAB sets are empty — no project hashes in the binary", () => {
  // Requirement 3: the maintainer's own prod+lab hashes must NOT ship in the package.
  // NOTE: this asserts only that no hash SHIPS — it is NOT a safety property. Empty
  // sets mean zero protection until an operator declares refs via env. The actual
  // protection is proven by group (g) below, which drives the env-sourced tiers.
  assert.equal(PERMANENT_BLOCKED_REF_HASHES.size, 0, "no permanent prod ref shipped");
  assert.equal(LAB_ELIGIBLE_REF_HASHES.size, 0, "no lab-eligible ref shipped");
});

// === (f) ref in neither set → not blocked ===

test("WO-19c (f): unblocked ref → not blocked", () => {
  withEnv({}, () => {
    const blocked = isBlockedRef("some-random-ref-11111");
    assert.equal(blocked, false, "a ref not in any set should not be blocked");
  });
});

// === (g) checkLabRef non-blocked ref still requires destructive flag ===

test("WO-19c (g): non-blocked ref requires --i-understand-this-is-destructive", () => {
  withEnv({}, () => {
    const r = checkLabRef("some-random-ref-11111", false);
    assert.equal(r.allowed, false, "lab commands require the destructive flag");
    assert.equal(r.isProd, false);
  });
});

test("WO-19c (g-2): non-blocked ref + destructive flag → allowed", () => {
  withEnv({}, () => {
    const r = checkLabRef("some-random-ref-11111", true);
    assert.equal(r.allowed, true, "non-blocked ref + flag → allowed");
    assert.equal(r.isProd, false);
  });
});


// === (g) env-sourced tiers — the REAL protection, since shipped sets are empty ===
//
// Regression guard for the 2026-08-31 incident: emptying the shipped sets removed all
// protection from the maintainer's production project, and routing that ref into
// SUPA360_BLOCKED_REFS did NOT restore it — that tier is unblockable by ceremony, so
// the self-reference hole reopened. Production belongs in SUPA360_PERMANENT_BLOCKED_REFS.
// These tests fail if tier 1 ever loses its env source or stops being a one-way door.

/** Async-safe counterpart of withEnv: awaits the body BEFORE restoring env.
 *  withEnv's `finally` runs as soon as an async fn returns its promise, which would
 *  restore the environment while the body is still running. */
async function withEnvAsync(env, fn) {
  const saved = {};
  for (const k of Object.keys(env)) {
    saved[k] = process.env[k];
    if (env[k] === undefined) delete process.env[k];
    else process.env[k] = env[k];
  }
  try {
    return await fn();
  } finally {
    for (const k of Object.keys(env)) {
      if (saved[k] === undefined) delete process.env[k];
      else process.env[k] = saved[k];
    }
  }
}

const ENV_PROD = "env-prod-ref-55555";
const ENV_LAB = "env-lab-ref-66666";

const CEREMONIES = [
  { name: "no ceremony", opts: {}, labRef: undefined },
  { name: "allowLab+ack, no SUPA360_LAB_REF", opts: { allowLab: true, destructiveAck: true }, labRef: undefined },
  { name: "allowLab+ack, SUPA360_LAB_REF=<other ref>", opts: { allowLab: true, destructiveAck: true }, labRef: ENV_LAB },
  { name: "allowLab+ack, SUPA360_LAB_REF=<SAME ref>", opts: { allowLab: true, destructiveAck: true }, labRef: ENV_PROD },
];

for (const c of CEREMONIES) {
  test(`WO-19c (g): SUPA360_PERMANENT_BLOCKED_REFS ref stays blocked — ${c.name}`, () => {
    withEnv({ SUPA360_PERMANENT_BLOCKED_REFS: ENV_PROD, SUPA360_BLOCKED_REFS: undefined, SUPA360_LAB_REF: c.labRef }, () => {
      assert.equal(isBlockedRef(ENV_PROD, c.opts), true,
        `permanent env ref must stay blocked under: ${c.name}`);
    });
  });
}

test("WO-19c (g): permanent env ref is never usable as a lab (checkLabRef)", () => {
  withEnv({ SUPA360_PERMANENT_BLOCKED_REFS: ENV_PROD, SUPA360_LAB_REF: ENV_PROD }, () => {
    const gate = checkLabRef(ENV_PROD, true);
    assert.equal(gate.allowed, false, "lab must refuse a permanent env ref");
    assert.equal(gate.isProd, true, "permanent env ref must be reported as production");
    assert.match(gate.reason, /permanently blocked/);
  });
});

test("WO-19c (g): rollbackRemediation refuses a permanent env ref under full ceremony", async () => {
  await withEnvAsync({ SUPA360_PERMANENT_BLOCKED_REFS: ENV_PROD, SUPA360_LAB_REF: ENV_PROD }, async () => {
    await assert.rejects(
      () => rollbackRemediation({ project_ref: ENV_PROD, plan: [] },
        { token: "not-a-real-token", allowLab: true, destructiveAck: true }),
      (e) => e.code === "PROD_REF_BLOCKED");
  });
});

test("WO-19c (g): remediate --apply refuses a permanent env ref under full ceremony", async () => {
  await withEnvAsync({ SUPA360_PERMANENT_BLOCKED_REFS: ENV_PROD, SUPA360_LAB_REF: ENV_PROD }, async () => {
    await assert.rejects(
      () => remediate({ project_ref: ENV_PROD, findings: [] },
        { dryRun: false, token: "not-a-real-token", allowLab: true, destructiveAck: true }),
      (e) => e.code === "PROD_REF_BLOCKED");
  });
});

test("WO-19c (g): the two tiers are NOT interchangeable — tier 2 IS unblockable by ceremony", () => {
  // This is precisely why a production ref must never be put in SUPA360_BLOCKED_REFS.
  withEnv({ SUPA360_PERMANENT_BLOCKED_REFS: undefined, SUPA360_BLOCKED_REFS: ENV_LAB, SUPA360_LAB_REF: ENV_LAB }, () => {
    assert.equal(isBlockedRef(ENV_LAB, {}), true, "tier 2 ref blocked without ceremony");
    assert.equal(isBlockedRef(ENV_LAB, { allowLab: true, destructiveAck: true }), false,
      "tier 2 ref IS unblocked by full ceremony — documents why production belongs in tier 1");
  });
});
