// Security DEFINER function body analyzer (pure, DB-free, unit-testable).
// Mirrors scripts/checks/rls.js + rpc.js: feed in structured function data
// and get findings out — zero live DB, no global.fetch mocking needed.
//
// Spec coverage (entry 10):
//  - analyze secdef functions executable by anon/authenticated (the dangerous set)
//  - Grade the internal auth check as strong/weak/none (NOT a binary flag):
//    strong = auth.uid/jwt/role, get_my_, is_admin; weak = bare current_setting/
//    company_id/tenant_id/user_id (a column/param name, NOT a guard); none = no signal.
//    weak & none are flagged (weak at reduced severity) — a weak mention must never
//    read as "safe" (the bug: target_user_id / company_id-as-column passed silently).
//  - Flag missing SET search_path (search_path injection) — complements the
//    existing function_no_search_path check with body-analysis context
//  - Flag dynamic SQL (EXECUTE/format) built from arguments without quoting
//    (EXECUTE without USING, or format() with %s and no %I/%L)

// Grade the authorization check in a SECURITY DEFINER body. A single binary
// "present/absent" regex is unsafe — company_id/tenant_id/user_id are column/parameter
// names that match but are NOT authorization checks, so weak guards read as safe. We
// grade instead and flag everything that isn't strongly guarded.
//   strong — auth.uid(), auth.jwt(), auth.role(), get_my_*, is_admin(...) (real auth context)
//   weak   — only a bare identity-ish mention (current_setting(, company_id, tenant_id,
//            user_id): no strong guard could be established -> flagged, reduced severity
//   none   — no auth signal at all -> critical
const STRONG_AUTH_CHECK_RE = /auth\.uid\(\)|auth\.jwt\(\)|auth\.role\(\)|get_my_|is_admin\(/i;
const WEAK_AUTH_CHECK_RE = /current_setting\(|company_id|tenant_id|user_id/i;

// Explicit, testable grade for a function body's auth check. Exported so every
// anon-executable SECURITY DEFINER function gets a grade (strong/weak/none) instead
// of relying on a boolean regex match that silently misclassifies weak refs.
export function classifyAuthCheck(body) {
  const b = body || "";
  if (STRONG_AUTH_CHECK_RE.test(b)) return "strong";
  if (WEAK_AUTH_CHECK_RE.test(b)) return "weak";
  return "none";
}

// Check proconfig (pg_proc.proconfig) for a SET search_path entry.
export function hasSearchPath(config) {
  return (
    Array.isArray(config) &&
    config.some(
      (c) => typeof c === "string" && c.toLowerCase().startsWith("search_path=")
    )
  );
}

// Detect unsafe dynamic SQL in a function body.
// Returns a human-readable reason if found, null if safe.
//   EXECUTE ... USING is safe (params auto-quoted by PostgreSQL).
//   format() with %I (identifier) or %L (literal) is safe (format quotes).
//   EXECUTE with string concat, or format(%s) without %I/%L, is FLAGGED.
export function detectDynamicSql(body) {
  if (!body) return null;
  const b = String(body);
  if (!/execute\s+/i.test(b)) return null; // no dynamic SQL at all

  // Safe: EXECUTE ... USING (parameters auto-quoted)
  if (/\busing\b/i.test(b)) return null;

  // Safe: format() with %I (identifier) or %L (literal) quoting
  if (/%[IL]/.test(b)) return null;

  // Unsafe: format() with %s (no %I/%L)
  if (/format\s*\(\s*['"]/i.test(b) && /%s/.test(b)) {
    return "format() uses %s interpolation without %I (identifier) or %L (literal) quoting";
  }

  // Unsafe: EXECUTE with string concatenation / interpolation
  return "EXECUTE without USING (arguments interpolated into query string)";
}

// Analyze one SECURITY DEFINER function body for authz + injection issues.
// fn: { function_name, prosecdef, body, config, anon_execute, auth_execute }
// returns: array of finding objects (each has fix.sql[]).
export function analyzeFunctionBody(fn) {
  if (!fn.prosecdef) return []; // only SECURITY DEFINER functions are analyzed

  const { function_name, schema_name, body, config } = fn;
  const findings = [];

  // 1. Grade the internal auth check (strong/weak/none). A strong guard means the
  //    function is genuinely authorized — no finding (the positive "not flagged" case).
  //    weak & none are flagged; weak at reduced severity so a bare company_id/user_id
  //    reference can never silently read as "safe" (the bug this fixes).
  const authCheck = classifyAuthCheck(body);
  if (authCheck !== "strong") {
    findings.push({
      check: "function_secdef_missing_auth_check",
      category: "coverage-rpc",
      severity: authCheck === "weak" ? "high" : "critical",
      confidence: "inferred",
      target: function_name,
      details: {
        auth_check: authCheck, // "weak" | "none" — explicit grade on every emitted auth finding
        has_auth_check: false,
        ...(authCheck === "weak"
          ? { auth_check_reason: "body references an identity-ish identifier (current_setting/company_id/tenant_id/user_id) but no strong auth guard (auth.uid/jwt/role/is_admin/get_my_); cannot confirm the function is authorized" }
          : {}),
        body_preview: (body || "").slice(0, 500),
      },
      fix: {
        sql: [
          `-- Add an internal authorization check inside the body, e.g. (best practice: (select auth.uid())):`,
          `--   IF (select auth.role()) = 'anon' THEN`,
          `--     RAISE EXCEPTION 'forbidden' USING ERRCODE = 'P0001';`,
          `--   END IF;`,
          `-- Or require a confirmed auth.uid() and scope all queries to it:`,
          `  IF (select auth.uid()) IS NULL THEN`,
          `    RAISE EXCEPTION 'unauthorized' USING ERRCODE = 'P0001';`,
          `  END IF;`,
          `-- Or restructure: move sensitive logic into a SECURITY INVOKER wrapper`,
          `-- gated by (select auth.uid()), keeping the defuser thin.`,
        ],
        rollback_sql: [`-- No automated rollback: the auth-check is a source-code change inside the function body. Revert the body edit manually (DROP the added IF-block / RAISE EXCEPTION).`],
        requires_service_role: false,
      },
    });
  }

  // 2. Missing SET search_path (search_path injection vector)
  if (!hasSearchPath(config)) {
    findings.push({
      check: "function_secdef_no_search_path",
      category: "coverage-rpc",
      severity: "medium",
      confidence: "inferred",
      target: function_name,
      details: { has_search_path: false },
      fix: {
        sql: [
          `ALTER FUNCTION ${schema_name || "public"}.${function_name} SET search_path = ${schema_name || "public"}, pg_temp;`,
        ],
        rollback_sql: [
          `ALTER FUNCTION ${schema_name || "public"}.${function_name} RESET search_path;`,
        ],
        requires_service_role: false,
      },
    });
  }

  // 3. Dynamic SQL built from arguments without quoting
  const dynReason = detectDynamicSql(body);
  if (dynReason) {
    findings.push({
      check: "function_secdef_dynamic_sql",
      category: "coverage-rpc",
      severity: "high",
      confidence: "inferred",
      target: function_name,
      details: { reason: dynReason, body_preview: (body || "").slice(0, 500) },
      fix: {
        sql: [
          `-- Use EXECUTE ... USING for parameters (auto-quoted):`,
          `  EXECUTE 'SELECT * FROM accounts WHERE id = $1' USING account_id;`,
          `-- Or use format() with %I (identifier) and %L (literal):`,
          `  EXECUTE format('SELECT * FROM %I WHERE id = %L', table_name, account_id);`,
        ],
        rollback_sql: [`-- No automated rollback: the dynamic-SQL fix is a source-code change inside the function body. Revert the body edit to restore the original EXECUTE/format() form.`],
        requires_service_role: false,
      },
    });
  }

  return findings;
}

// Filter to secdef + anon/auth-executable, then analyze bodies.
// functions: [{ function_name, prosecdef, body, config, anon_execute, auth_execute }]
// returns: flat array of findings.
export function analyzeFunctionBodies(functions) {
  return functions
    .filter((f) => f.prosecdef && (f.anon_execute || f.auth_execute))
    .flatMap((f) => analyzeFunctionBody(f));
}
