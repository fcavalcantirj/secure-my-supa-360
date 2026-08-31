// Unit tests for the pure RPC exposure classifier (+ active-probe driver).
// No live DB: a fake async probeFn stub the transport. Run: node --test test/rpc.test.js
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  buildSafePayload,
  parseArgSignature,
  classifyRpc,
  probeRpcs,
} from "../scripts/checks/rpc.js";

const NIL = "00000000-0000-0000-0000-000000000000";

test("buildSafePayload: null for scalars, nil UUID for uuid, skips OUT/TABLE, [] for variadic", () => {
  const fn = {
    args: [
      { name: "p_company", type: "uuid", mode: "i" },
      { name: "p_label", type: "text", mode: "i" },
      { name: "p_inout", type: "int4", mode: "b" },
      { name: "p_variadic", type: "int4", mode: "v" },
      { name: "p_out", type: "text", mode: "o" },
      { name: "p_table", type: "text", mode: "t" },
    ],
  };
  const payload = buildSafePayload(fn);
  assert.equal(payload.p_company, NIL);
  assert.equal(payload.p_label, null);
  assert.equal(payload.p_inout, null);
  assert.deepEqual(payload.p_variadic, []);
  assert.equal(payload.p_out, undefined);
  assert.equal(payload.p_table, undefined);
});

test("parseArgSignature: handles named/unnamed args + type modifiers with commas", () => {
  assert.deepEqual(parseArgSignature(""), []);
  const a = parseArgSignature("p_company uuid, p_amount numeric(10,2), a timestamp with time zone, integer");
  assert.equal(a.length, 4);
  assert.equal(a[0].name, "p_company");
  assert.equal(a[0].type, "uuid");
  assert.equal(a[1].name, "p_amount");
  assert.equal(a[1].type, "numeric(10,2)"); // comma inside () preserved
  assert.equal(a[2].type, "timestamp with time zone");
  assert.equal(a[3].name, "arg4"); // unnamed -> generic
  assert.equal(a[3].type, "integer");
});

test("classifyRpc: 200/204 executed -> confirmed exploited", () => {
  const fn = { function_name: "f", prosecdef: false };
  assert.deepEqual(classifyRpc(fn, { status: 200, body: "[]" }), { exploited: true, confirmed: true, confidence: "confirmed", blocked: false, reason: "HTTP 200 (executed)", status: 200 });
  assert.equal(classifyRpc(fn, { status: 204, body: "" }).exploited, true);
});

test("classifyRpc: 42501/401/404/null -> inferred, not exploited (gated/not-exposed)", () => {
  const fn = { function_name: "f", prosecdef: false };
  assert.equal(classifyRpc(fn, { status: 42501, body: "" }).confidence, "inferred");
  assert.equal(classifyRpc(fn, { status: 42501, body: "" }).exploited, false);
  assert.equal(classifyRpc(fn, { status: 401, body: "" }).confidence, "inferred");
  assert.equal(classifyRpc(fn, { status: 404, body: "" }).confidence, "inferred");
  assert.equal(classifyRpc(fn, null).confidence, "inferred");
  assert.equal(classifyRpc(fn, null).exploited, false);
});

test("classifyRpc: business-error SQLSTATE -> confirmed (body executed, no auth gate)", () => {
  const fn = { function_name: "attach_company_admin", prosecdef: true };
  const probe = { status: 500, body: JSON.stringify({ code: "P0001", message: "company not found" }) };
  const cls = classifyRpc(fn, probe);
  assert.equal(cls.confirmed, true);
  assert.equal(cls.exploited, true);
  assert.equal(cls.confidence, "confirmed");
  assert.equal(cls.status, 500);
});

test("probeRpcs: attach_company_admin business-error -> confirmed (critical for secdef); membership-gated 42501 -> not confirmed; summary split", async () => {
  const functions = [
    {
      function_name: "attach_company_admin",
      prosecdef: true, provolatile: "v", return_type: "jsonb",
      anon_execute: true, auth_execute: true, config: [],
      args: [{ name: "p_company", type: "uuid", mode: "i" }],
    },
    {
      function_name: "get_my_memberships",
      prosecdef: false, provolatile: "s", return_type: "SETOF membership",
      anon_execute: true, auth_execute: true, config: [],
      args: [],
    },
    {
      function_name: "internal_secret_fn",
      prosecdef: false, provolatile: "s", return_type: "void",
      anon_execute: false, auth_execute: true, config: [],
      args: [],
    },
  ];
  // fake async probe transport
  const probeFn = async (fnName, payload) => {
    if (fnName === "attach_company_admin") {
      return { status: 500, body: JSON.stringify({ code: "P0001", message: "company not found" }) };
    }
    if (fnName === "get_my_memberships") {
      return { status: 42501, body: JSON.stringify({ code: "42501", message: "permission denied" }) };
    }
    return { status: 404, body: "" };
  };
  const { findings, confirmed_count, inferred_count } = await probeRpcs(functions, probeFn, true);

  // Non-anon-executable fns are skipped entirely.
  assert.equal(findings.length, 2, "internal_secret_fn (auth_execute-only) must be skipped");

  const a = findings.find((f) => f.target === "attach_company_admin");
  assert.ok(a, "attach_company_admin should produce a finding");
  assert.equal(a.check, "rpc_confirmed_executable");
  assert.equal(a.confidence, "confirmed");
  assert.equal(a.exploitable_without_auth, true);
  assert.equal(a.severity, "critical"); // secdef + confirmed -> critical
  assert.equal(a.evidence.payload.p_company, NIL);
  assert.equal(a.evidence.probe.status, 500);

  const g = findings.find((f) => f.target === "get_my_memberships");
  assert.ok(g, "get_my_memberships should produce a finding");
  assert.equal(g.check, "rpc_granted_inferred");
  assert.equal(g.confidence, "inferred");
  assert.equal(g.exploitable_without_auth, false);
  assert.equal(g.severity, "low");
  assert.equal(g.evidence.probe.status, 42501);

  // summary split (this is what kills the over-count)
  assert.equal(confirmed_count, 1);
  assert.equal(inferred_count, 1);
});

test("probeRpcs: volatile function NOT probed by default -> reported as inferred, not confirmed", async () => {
  const functions = [
    { function_name: "send_webhook", prosecdef: true, provolatile: "v", return_type: "void",
      anon_execute: true, config: null, args: [] },
  ];
  const probeFn = async () => assert.fail("probeFn should NOT be called for volatile functions");
  const { findings, confirmed_count, inferred_count } = await probeRpcs(functions, probeFn);
  // No probeVolatile -> volatile fn skipped from probing but still reported
  assert.equal(findings.length, 1);
  assert.equal(findings[0].confidence, "inferred");
  assert.equal(findings[0].check, "rpc_granted_inferred");
  assert.equal(confirmed_count, 0);
  assert.equal(inferred_count, 1);
});

test("probeRpcs: volatile function IS probed when probeVolatile=true", async () => {
  const functions = [
    { function_name: "send_webhook", prosecdef: false, provolatile: "v", return_type: "void",
      anon_execute: true, config: null, args: [] },
  ];
  let probed = false;
  const probeFn = async (fnName) => { probed = true; return { status: 200, body: "[]" }; };
  const { findings, confirmed_count } = await probeRpcs(functions, probeFn, true);
  assert.ok(probed, "volatile fn IS probed when probeVolatile=true");
  assert.equal(findings[0].confidence, "confirmed");
  assert.equal(confirmed_count, 1);
});

test("probeRpcs: volatile fn without --probe-volatile -> still reported, inferred", async () => {
  // Volatile functions are still ENUMERATED and REPORTED — just not probed.
  // We lose confirmation, not the finding.
  const functions = [
    { function_name: "send_email", prosecdef: true, provolatile: "v", return_type: "void",
      anon_execute: true, config: null, args: [{ name: "p_id", type: "uuid", mode: "i" }] },
    { function_name: "get_count", prosecdef: false, provolatile: "s", return_type: "integer",
      anon_execute: true, config: null, args: [] },
  ];
  let volatileProbed = false;
  const probeFn = async (fnName) => {
    if (fnName === "send_email") volatileProbed = true;
    return { status: 200, body: "[{\"count\":0}]" };
  };
  const { findings, confirmed_count, inferred_count } = await probeRpcs(functions, probeFn);
  // Both functions reported as findings
  assert.equal(findings.length, 2);
  // Volatile fn NOT probed, reported as inferred
  const volatile = findings.find((f) => f.target === "send_email");
  assert.ok(volatile, "volatile fn still reported");
  assert.equal(volatile.confidence, "inferred");
  assert.equal(volatile.evidence.probe, undefined, "no probe data for volatile fn");
  // Stable fn IS probed, reported as confirmed
  const stable = findings.find((f) => f.target === "get_count");
  assert.equal(stable.confidence, "confirmed");
  assert.ok(!volatileProbed, "volatile fn must NOT be probed");
  assert.equal(confirmed_count, 1);
  assert.equal(inferred_count, 1);
});
