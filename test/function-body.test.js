import { test } from "node:test";
import assert from "node:assert/strict";
import {
  analyzeFunctionBody,
  analyzeFunctionBodies,
  classifyAuthCheck,
  hasSearchPath,
  detectDynamicSql,
} from "../scripts/checks/function-body.js";

test("hasSearchPath detects SET search_path in proconfig", () => {
  assert.equal(hasSearchPath(["search_path=public,pg_temp"]), true);
  assert.equal(hasSearchPath(["search_path=public"]), true);
  assert.equal(hasSearchPath(["statement_mem=262144"]), false);
  assert.equal(hasSearchPath([]), false);
  assert.equal(hasSearchPath(null), false);
});

test("detectDynamicSql: EXECUTE without USING -> flagged; USING -> safe", () => {
  assert.ok(detectDynamicSql("EXECUTE 'SELECT * FROM t WHERE id = ' || x"));
  assert.equal(detectDynamicSql("EXECUTE 'SELECT * FROM t WHERE id = $1' USING x"), null);
  assert.equal(detectDynamicSql("SELECT * FROM t WHERE id = 1"), null);
});

test("detectDynamicSql: format(%s) without %I/%L -> flagged; with %I/%L -> safe", () => {
  assert.ok(detectDynamicSql("EXECUTE format('SELECT * FROM %s WHERE id = %s', t, v)"));
  assert.equal(detectDynamicSql("EXECUTE format('SELECT * FROM %I WHERE id = %L', t, v)"), null);
  assert.ok(detectDynamicSql("EXECUTE 'SELECT * FROM t' || x"), "bare EXECUTE without USING is flagged");
});

// Note: "EXECUTE 'SELECT * FROM t'" has EXECUTE without USING and no %I/%L -> flagged
test("detectDynamicSql: bare EXECUTE string concat -> flagged", () => {
  assert.ok(detectDynamicSql("EXECUTE 'SELECT * FROM t' || x"));
});

test("secdef fn: no auth check + dynamic SQL + search_path set -> exactly 2 findings", () => {
  const fn = {
    function_name: "transfer_funds",
    prosecdef: true,
    config: ["search_path=public,pg_temp"],
    body: "BEGIN EXECUTE 'SELECT * FROM accounts WHERE id = ' || account_id || '; UPDATE accounts SET bal = bal - amount WHERE id = ' || account_id; RETURN; END;",
    anon_execute: true,
    auth_execute: true,
  };
  const findings = analyzeFunctionBody(fn);
  assert.equal(findings.length, 2);
  const checks = findings.map((f) => f.check);
  assert.ok(
    checks.includes("function_secdef_missing_auth_check"),
    `expected missing_auth_check, got: ${checks.join(", ")}`
  );
  const missing = findings.find((f) => f.check === "function_secdef_missing_auth_check");
  assert.equal(missing.severity, "critical");

  const dyn = findings.find((f) => f.check === "function_secdef_dynamic_sql");
  assert.ok(dyn, "expected dynamic_sql finding");
  assert.equal(dyn.severity, "high");
});

test("secdef fn: with auth check + EXECUTE USING + search_path -> no findings (safe)", () => {
  const fn = {
    function_name: "safe_transfer",
    prosecdef: true,
    config: ["search_path=public"],
    body: "BEGIN IF auth.uid() IS NOT NULL THEN EXECUTE 'SELECT * FROM accounts WHERE owner_id = $1' USING account_id; RETURN account_id; END IF; END;",
    anon_execute: true,
    auth_execute: true,
  };
  assert.equal(analyzeFunctionBody(fn).length, 0);
});

test("secdef fn: missing search_path (config null) -> no_search_path finding only", () => {
  const fn = {
    function_name: "no_path_fn",
    prosecdef: true,
    config: null,
    body: "BEGIN IF auth.uid() IS NOT NULL THEN RETURN 1; END IF; END;",
    anon_execute: false,
    auth_execute: true,
  };
  const findings = analyzeFunctionBody(fn);
  const checks = findings.map((f) => f.check);
  assert.ok(
    checks.includes("function_secdef_no_search_path"),
    `expected no_search_path, got: ${checks.join(", ")}`
  );
  assert.ok(
    !checks.includes("function_secdef_missing_auth_check"),
    "auth.uid present should prevent missing_auth_check"
  );
  assert.ok(
    !checks.includes("function_secdef_dynamic_sql"),
    "no EXECUTE -> no dynamic_sql finding"
  );
});

test("invoker function -> no body analysis findings", () => {
  const fn = {
    function_name: "normal_proc",
    prosecdef: false,
    config: [],
    body: "BEGIN PERFORM something(); RETURN 1; END;",
    anon_execute: true,
    auth_execute: true,
  };
  assert.equal(analyzeFunctionBody(fn).length, 0);
});

test("analyzeFunctionBodies: filters to secdef + anon/auth-executable, flattens findings", () => {
  const functions = [
    { function_name: "no_auth_check", prosecdef: true, config: ["search_path=public"], body: "BEGIN PERFORM x(); RETURN 1; END;", anon_execute: true, auth_execute: false },
    { function_name: "invoker_fn", prosecdef: false, config: [], body: "BEGIN PERFORM x(); RETURN 1; END;", anon_execute: true, auth_execute: true },
    { function_name: "no_grant_fn", prosecdef: true, config: ["search_path=public"], body: "BEGIN PERFORM x(); RETURN 1; END;", anon_execute: false, auth_execute: false },
  ];
  const findings = analyzeFunctionBodies(functions);
  // Only "no_auth_check" is secdef + anon_executable -> 1 finding (missing_auth_check)
  assert.equal(findings.length, 1);
  assert.equal(findings[0].check, "function_secdef_missing_auth_check");
  assert.equal(findings[0].target, "no_auth_check");
});

// === #4: graded auth-check signal (strong/weak/none) ===
// The old AUTH_CHECK_RE matched `user_id`/`company_id` as "guards", so weak refs
// read as safe and were silently absent from output. These four bodies assert the
// three tiers (weak appears twice — the exact bug class being fixed).

const BODY_NONE =
  "BEGIN UPDATE accounts SET bal = bal - amount WHERE id = 'x'; RETURN; END;";
const BODY_WEAK_PARAM =
  "BEGIN UPDATE notes SET owner_id = target_user_id WHERE id = 1; RETURN; END;"; // target_user_id is a param, not a guard
const BODY_WEAK_COL =
  "BEGIN INSERT INTO notes (company_id, data) VALUES (1, 'x'); RETURN; END;"; // company_id as an INSERT column, not a guard
const BODY_STRONG =
  "BEGIN IF (select auth.uid()) IS NULL THEN RAISE EXCEPTION 'forbidden' USING ERRCODE = 'P0001'; END IF; UPDATE notes SET data = 'x'; RETURN; END;";

test("#4 classifyAuthCheck: grades the four reference bodies (none / weak / weak / strong)", () => {
  assert.equal(classifyAuthCheck(BODY_NONE), "none");
  assert.equal(classifyAuthCheck(BODY_WEAK_PARAM), "weak", "target_user_id is a param name, not an auth guard");
  assert.equal(classifyAuthCheck(BODY_WEAK_COL), "weak", "company_id as a column is not an auth guard");
  assert.equal(classifyAuthCheck(BODY_STRONG), "strong", "real auth.uid() guard");
});

test("#4 classifyAuthCheck: empty/undefined body -> none (no false strong signal)", () => {
  assert.equal(classifyAuthCheck(""), "none");
  assert.equal(classifyAuthCheck(undefined), "none");
});

test("#4: weak ref (target_user_id) is FLAGGED, not silent — evidence.auth_check='weak', reduced severity", () => {
  const fn = {
    function_name: "promote_to_admin", schema_name: "public", prosecdef: true,
    config: ["search_path=public"], body: BODY_WEAK_PARAM, anon_execute: true, auth_execute: false,
  };
  const findings = analyzeFunctionBody(fn);
  const miss = findings.find((f) => f.check === "function_secdef_missing_auth_check");
  assert.ok(miss, "a weak guard must emit a finding (was silently absent by the bug)");
  assert.equal(miss.severity, "high", "weak = reduced severity, not critical");
  assert.equal(miss.details.auth_check, "weak");
  assert.ok(/cannot confirm the function is authorized/.test(miss.details.auth_check_reason));
});

test("#4: weak ref (company_id as column) is FLAGGED, not silent", () => {
  const fn = {
    function_name: "write_note", schema_name: "public", prosecdef: true,
    config: ["search_path=public"], body: BODY_WEAK_COL, anon_execute: true, auth_execute: false,
  };
  const findings = analyzeFunctionBody(fn);
  const miss = findings.find((f) => f.check === "function_secdef_missing_auth_check");
  assert.ok(miss, "company_id-as-column must emit a finding (was silently absent by the bug)");
  assert.equal(miss.details.auth_check, "weak");
  assert.equal(miss.severity, "high");
});

test("#4: a strong guard emits NO missing_auth_check finding (positive 'not flagged')", () => {
  const fn = {
    function_name: "is_authorized", schema_name: "public", prosecdef: true,
    config: ["search_path=public"], body: BODY_STRONG, anon_execute: true, auth_execute: false,
  };
  const findings = analyzeFunctionBody(fn);
  assert.equal(findings.find((f) => f.check === "function_secdef_missing_auth_check"), undefined);
  assert.equal(findings.length, 0, "strong guard + search_path + no dynamic SQL -> no findings");
});

test("#4: a true missing guard (none) stays critical with evidence.auth_check='none'", () => {
  const fn = {
    function_name: "blind_write", schema_name: "public", prosecdef: true,
    config: ["search_path=public"], body: BODY_NONE, anon_execute: true, auth_execute: false,
  };
  const findings = analyzeFunctionBody(fn);
  const miss = findings.find((f) => f.check === "function_secdef_missing_auth_check");
  assert.ok(miss);
  assert.equal(miss.severity, "critical");
  assert.equal(miss.details.auth_check, "none");
});
