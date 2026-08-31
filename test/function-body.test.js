import { test } from "node:test";
import assert from "node:assert/strict";
import {
  analyzeFunctionBody,
  analyzeFunctionBodies,
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
