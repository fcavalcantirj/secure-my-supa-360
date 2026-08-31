import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import {
  classifyEdgeFunction,
  processEdgeFunctions,
  analyzeEdgeFunctionBody,
  fnApiPath,
} from "../scripts/checks/edge_functions.js";
import { normalizeFinding, assembleResult, scanForSecrets } from "../scripts/contract.js";
import { validate } from "../scripts/validate.js";

const SCHEMA_PATH = fileURLToPath(new URL("../schema/finding.schema.json", import.meta.url));
const schema = JSON.parse(readFileSync(SCHEMA_PATH, "utf8"));

// ---------------------------------------------------------------------------
// analyzeEdgeFunctionBody
// ---------------------------------------------------------------------------

test("analyzeEdgeFunctionBody: secret reading patterns detected", () => {
  const body = `
    import { serve } from "https://deno.land/std/http/server.ts";
    serve(async (req) => {
      const apiKey = Deno.env.get("MY_SECRET_API_KEY");
      console.log("API key is:", apiKey);
      return new Response(JSON.stringify({ key: apiKey }));
    });
  `;
  const result = analyzeEdgeFunctionBody(body);
  assert.ok(result, "expected analysis result");
  assert.equal(result.reading, true, "should detect secret reading");
  assert.equal(result.echoing, true, "should detect echoing/logging");
  assert.equal(result.writing, false);
});

test("analyzeEdgeFunctionBody: write operations detected", () => {
  const body = `
    const { data, error } = await supabase.from("orders").insert({ user_id: 1, total: 100 });
    const { data: updated } = await supabase.from("profiles").update({ name: "x" }).eq("id", 1);
    await supabase.from("sessions").delete().match({ id: 1 });
  `;
  const result = analyzeEdgeFunctionBody(body);
  assert.ok(result);
  assert.equal(result.reading, false);
  assert.equal(result.echoing, false);
  assert.equal(result.writing, true, "should detect write operations");
});

test("analyzeEdgeFunctionBody: clean body -> all false", () => {
  const body = `
    serve(async (req) => {
      const { data } = await supabase.from("posts").select("*");
      return new Response(JSON.stringify({ data }));
    });
  `;
  const result = analyzeEdgeFunctionBody(body);
  assert.ok(result);
  assert.equal(result.reading, false);
  assert.equal(result.echoing, false);
  assert.equal(result.writing, false);
});

test("analyzeEdgeFunctionBody: null/empty body -> null", () => {
  assert.equal(analyzeEdgeFunctionBody(null), null);
  assert.equal(analyzeEdgeFunctionBody(""), null);
  assert.equal(analyzeEdgeFunctionBody(undefined), null);
  assert.equal(analyzeEdgeFunctionBody(123), null);
});

test("analyzeEdgeFunctionBody: process.env and Deno.secrets detected as reading", () => {
  assert.equal(analyzeEdgeFunctionBody("const k = process.env.SECRET_KEY;").reading, true);
  assert.equal(analyzeEdgeFunctionBody("const s = Deno.secrets.").reading, true);
  assert.equal(analyzeEdgeFunctionBody("const v = Deno.env.get('TOKEN');").reading, true);
});

test("analyzeEdgeFunctionBody: SQL INSERT/UPDATE/DELETE detected as writing", () => {
  assert.equal(analyzeEdgeFunctionBody("await supabase.rpc('admin_op'); INSERT INTO logs VALUES(1);").writing, true);
  assert.equal(analyzeEdgeFunctionBody("UPDATE users SET role='admin' WHERE id=1;").writing, true);
  assert.equal(analyzeEdgeFunctionBody("DELETE FROM temp_data;").writing, true);
});

// ---------------------------------------------------------------------------
// classifyEdgeFunction — verify_jwt
// ---------------------------------------------------------------------------

test("verify_jwt=false -> edge_function_verify_jwt_disabled (high, confirmed) + management_api_action", () => {
  const fn = {
    id: "fn-123",
    name: "process-payment",
    slug: "process-payment",
    verify_jwt: false,
    import_map: false,
    status: "ACTIVE",
    cors: false,
  };
  const findings = classifyEdgeFunction(fn, "myproject");
  assert.equal(findings.length, 1);
  const f = findings[0];
  assert.equal(f.check, "edge_function_verify_jwt_disabled");
  assert.equal(f.severity, "high");
  assert.equal(f.confidence, "confirmed");
  assert.equal(f.category, "coverage-edge-functions");
  assert.equal(f.target, "function:fn-123");
  assert.equal(f.evidence.verify_jwt, false);
  assert.equal(f.evidence.name, "process-payment");
  assert.ok(f.fix.management_api_action, "should have management_api_action");
  assert.equal(f.fix.management_api_action.method, "PATCH");
  assert.equal(f.fix.management_api_action.path, "/v1/projects/myproject/functions/fn-123");
  assert.deepEqual(f.fix.management_api_action.body, { verify_jwt: true });
  assert.equal(f.fix.requires_service_role, false);
});

test("verify_jwt=true -> no finding (safe)", () => {
  const fn = {
    id: "fn-456",
    name: "user-profile",
    verify_jwt: true,
    cors: false,
    status: "ACTIVE",
  };
  const findings = classifyEdgeFunction(fn, "ref");
  assert.equal(findings.length, 0);
});

test("verify_jwt omitted (undefined) -> no finding (safe, default is JWT-enforced in supabase)", () => {
  const fn = { id: "fn-789", name: "safe-fn", status: "ACTIVE" };
  const findings = classifyEdgeFunction(fn, "ref");
  assert.equal(findings.length, 0);
});

// ---------------------------------------------------------------------------
// classifyEdgeFunction — CORS
// ---------------------------------------------------------------------------

test("wildcard CORS (cors=true) -> edge_function_wildcard_cors (medium, confirmed)", () => {
  const fn = {
    id: "fn-cors",
    name: "public-api",
    verify_jwt: true,
    cors: true,
  };
  const findings = classifyEdgeFunction(fn, "ref");
  assert.equal(findings.length, 1);
  const f = findings[0];
  assert.equal(f.check, "edge_function_wildcard_cors");
  assert.equal(f.severity, "medium");
  assert.equal(f.confidence, "confirmed");
  assert.equal(f.target, "function:fn-cors");
  assert.equal(f.evidence.cors, true);
  assert.equal(f.fix.management_api_action.method, "PATCH");
  assert.deepEqual(f.fix.management_api_action.body, { cors: false });
  assert.ok(f.fix.dashboard_action, "should also have dashboard_action");
});

test("CORS string wildcard '*' -> flagged", () => {
  const fn = { id: "fn-1", name: "star", verify_jwt: true, cors: "*" };
  const findings = classifyEdgeFunction(fn, "ref");
  assert.equal(findings.length, 1);
  assert.equal(findings[0].check, "edge_function_wildcard_cors");
});

test("cors=false -> no CORS finding", () => {
  const fn = { id: "fn-2", name: "secure", verify_jwt: true, cors: false };
  const findings = classifyEdgeFunction(fn, "ref");
  assert.equal(findings.length, 0);
});

// ---------------------------------------------------------------------------
// classifyEdgeFunction — secret echo (body analysis)
// ---------------------------------------------------------------------------

test("secret echo: body reads env + logs -> edge_function_secret_echo (high, inferred)", () => {
  const body = `
    const key = Deno.env.get("DB_PASSWORD");
    console.log("debug:", key);
    return new Response("ok");
  `;
  const fn = {
    id: "fn-secret",
    name: "config-check",
    verify_jwt: true,
    cors: false,
    body,
  };
  const findings = classifyEdgeFunction(fn, "ref");
  // verify_jwt is true, cors is false — only the secret_echo finding
  assert.equal(findings.length, 1);
  const f = findings[0];
  assert.equal(f.check, "edge_function_secret_echo");
  assert.equal(f.severity, "high");
  assert.equal(f.confidence, "inferred");
  assert.equal(f.evidence.body_analysis.reading, true);
  assert.equal(f.evidence.body_analysis.echoing, true);
});

test("secret echo: body reads env but does NOT echo -> no secret_echo finding", () => {
  const body = `
    const key = Deno.env.get("DB_PASSWORD");
    // use key internally, never logged or returned
    const { data } = await supabase.from("secrets").insert({ token: key });
  `;
  const fn = { id: "fn-ok", name: "internal", verify_jwt: true, cors: false, body };
  const findings = classifyEdgeFunction(fn, "ref");
  assert.equal(findings.length, 0);
});

// ---------------------------------------------------------------------------
// classifyEdgeFunction — unauthenticated write
// ---------------------------------------------------------------------------

test("unauthenticated write: verify_jwt=false + body has writes -> edge_function_unauthenticated_write (critical)", () => {
  const body = `
    const { data } = await supabase.from("orders").insert({ amount: 100 });
    return new Response(JSON.stringify({ data }));
  `;
  const fn = {
    id: "fn-write",
    name: "create-order",
    verify_jwt: false,
    cors: false,
    body,
  };
  const findings = classifyEdgeFunction(fn, "ref");
  // verify_jwt=false -> verify_jwt_disabled finding
  // verify_jwt=false + writes -> unauthenticated_write finding
  assert.equal(findings.length, 2);
  const checks = findings.map((f) => f.check).sort();
  assert.deepEqual(checks, ["edge_function_unauthenticated_write", "edge_function_verify_jwt_disabled"]);

  const writeF = findings.find((f) => f.check === "edge_function_unauthenticated_write");
  assert.equal(writeF.severity, "critical");
  assert.equal(writeF.confidence, "inferred");
  assert.equal(writeF.evidence.body_analysis.writing, true);
  assert.ok(writeF.evidence.reason);
});

test("unauthenticated write: verify_jwt=true + body has writes -> no unauthenticated_write (auth enforces)", () => {
  const body = `const { data } = await supabase.from("orders").insert({ amount: 100 });`;
  const fn = { id: "fn-auth-write", name: "create-order", verify_jwt: true, body };
  const findings = classifyEdgeFunction(fn, "ref");
  assert.equal(findings.length, 0);
});

// ---------------------------------------------------------------------------
// classifyEdgeFunction — multiple issues on one function
// ---------------------------------------------------------------------------

test("function with verify_jwt=false + wildcard CORS + secret echo -> 3 findings", () => {
  const body = `
    const k = Deno.env.get("API_KEY");
    console.log("key:", k);
    return new Response(JSON.stringify({ key: k }));
  `;
  const fn = {
    id: "fn-multi",
    name: "leaky-fn",
    verify_jwt: false,
    cors: true,
    body,
  };
  const findings = classifyEdgeFunction(fn, "ref");
  assert.equal(findings.length, 3);
  const checks = findings.map((f) => f.check).sort();
  assert.deepEqual(checks, [
    "edge_function_secret_echo",
    "edge_function_verify_jwt_disabled",
    "edge_function_wildcard_cors",
  ]);
});

// ---------------------------------------------------------------------------
// classifyEdgeFunction — edge cases
// ---------------------------------------------------------------------------

test("null/undefined fn -> []", () => {
  assert.equal(classifyEdgeFunction(null, "ref").length, 0);
  assert.equal(classifyEdgeFunction(undefined, "ref").length, 0);
});

test("fn with no id uses slug or name as target", () => {
  const fn = { name: "f1", verify_jwt: false };
  const findings = classifyEdgeFunction(fn, "ref");
  assert.equal(findings.length, 1);
  assert.equal(findings[0].target, "function:f1");
  assert.equal(findings[0].fix.management_api_action.path, "/v1/projects/ref/functions/f1");
});

// ---------------------------------------------------------------------------
// processEdgeFunctions
// ---------------------------------------------------------------------------

test("processEdgeFunctions: collects findings from all functions", () => {
  const functions = [
    { id: "fn-1", name: "safe-fn", verify_jwt: true, cors: false },
    { id: "fn-2", name: "insecure-fn", verify_jwt: false, cors: true },
    { id: "fn-3", name: "cors-only", verify_jwt: true, cors: true },
  ];
  const findings = processEdgeFunctions(functions, "myproject");
  // fn-2: verify_jwt_disabled + wildcard_cors = 2
  // fn-3: wildcard_cors = 1
  // fn-1: 0
  assert.equal(findings.length, 3);
  const targets = findings.map((f) => f.target).sort();
  assert.deepEqual(targets, ["function:fn-2", "function:fn-2", "function:fn-3"]);
});

test("processEdgeFunctions: empty array -> []", () => {
  assert.deepEqual(processEdgeFunctions([], "ref"), []);
  assert.deepEqual(processEdgeFunctions(null, "ref"), []);
});

test("processEdgeFunctions: all safe -> []", () => {
  const functions = [
    { id: "fn-1", name: "a", verify_jwt: true, cors: false },
    { id: "fn-2", name: "b", verify_jwt: true, cors: false },
  ];
  assert.equal(processEdgeFunctions(functions, "ref").length, 0);
});

// ---------------------------------------------------------------------------
// GOLDEN fixture (spec step 5): a function with verify_jwt disabled -> flagged high
// ---------------------------------------------------------------------------

test("GOLDEN fixture (spec step 5): verify_jwt disabled function is flagged high", () => {
  // Simulates the Management API listing + details response for a function
  // with verify_jwt=false, which makes it publicly invokable.
  const functions = [
    {
      id: "a1b2c3d4",
      name: "public-webhook",
      slug: "public-webhook",
      status: "ACTIVE",
      verify_jwt: false,
      import_map: true,
      cors: false,
    },
  ];
  const findings = processEdgeFunctions(functions, "testref01");
  assert.equal(findings.length, 1);
  const f = findings[0];
  assert.equal(f.check, "edge_function_verify_jwt_disabled");
  assert.equal(f.severity, "high");
  assert.equal(f.confidence, "confirmed");
  assert.equal(f.target, "function:a1b2c3d4");
  assert.equal(f.evidence.name, "public-webhook");
  assert.equal(f.evidence.verify_jwt, false);
  assert.equal(f.evidence.import_map, true);
  assert.equal(f.fix.management_api_action.method, "PATCH");
  assert.equal(f.fix.management_api_action.path, "/v1/projects/testref01/functions/a1b2c3d4");
  assert.deepEqual(f.fix.management_api_action.body, { verify_jwt: true });
});

// ---------------------------------------------------------------------------
// fnApiPath
// ---------------------------------------------------------------------------

test("fnApiPath: builds correct Management API path", () => {
  assert.equal(
    fnApiPath("myref", "fn-id-123"),
    "/v1/projects/myref/functions/fn-id-123"
  );
});

// ---------------------------------------------------------------------------
// Round-trip: normalize -> assembleResult -> schema valid + no secrets + deterministic
// ---------------------------------------------------------------------------

test("edge_functions findings round-trip: normalize -> assembleResult -> schema valid + no secrets + deterministic", () => {
  const functions = [
    {
      id: "fn-leaky",
      name: "leaky-endpoint",
      slug: "leaky-endpoint",
      verify_jwt: false,
      cors: true,
      status: "ACTIVE",
      import_map: false,
    },
    {
      id: "fn-safe",
      name: "secure-endpoint",
      verify_jwt: true,
      cors: false,
      status: "ACTIVE",
    },
  ];
  const rawFindings = processEdgeFunctions(functions, "xyz789");
  const normalized = rawFindings.map(normalizeFinding);

  const fixedAt = "2026-08-27T12:00:00.000Z";
  const result = assembleResult({
    project_ref: "xyz789",
    mode: "audit-passive",
    rawFindings: normalized,
    generated_at: fixedAt,
  });

  // 1. Schema validation
  const { valid, errors } = validate(result, schema);
  assert.equal(valid, true, `schema violations: ${JSON.stringify(errors)}`);

  // 2. No secrets in output
  const jsonStr = JSON.stringify(result);
  assert.equal(scanForSecrets(jsonStr).length, 0, "secrets leaked in output");

  // 3. Deterministic ordering — run twice, assert identical
  const json1 = JSON.stringify(assembleResult({
    project_ref: "xyz789",
    mode: "audit-passive",
    rawFindings: normalized,
    generated_at: fixedAt,
  }), null, 2);
  const json2 = JSON.stringify(assembleResult({
    project_ref: "xyz789",
    mode: "audit-passive",
    rawFindings: normalized,
    generated_at: fixedAt,
  }), null, 2);
  assert.equal(json1, json2, "output must be deterministic");

  // Verify the findings are present and correct
  assert.equal(result.findings.length, 2); // verify_jwt_disabled + wildcard_cors for fn-leaky
  const checks = result.findings.map((f) => f.check).sort();
  assert.deepEqual(checks, [
    "edge_function_verify_jwt_disabled",
    "edge_function_wildcard_cors",
  ]);
});
