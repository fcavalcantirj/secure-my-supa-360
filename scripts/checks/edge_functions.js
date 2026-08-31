// Edge Functions security auditor (pure, DB-free, unit-testable).
//
// Spec entry 17 (coverage-edge-functions):
//  - List edge functions via the Supabase Management API; for each read the
//    verify_jwt setting and CORS config.
//  - Flag verify_jwt=false (publicly invokable) functions and wildcard CORS.
//  - Flag functions that read secrets and echo/log them, or accept
//    unauthenticated writes (body analysis).
//  - Emit remediation as management_api_action (PATCH verify_jwt / cors) or
//    dashboard_action.
//
// Mirrors scripts/checks/rls.js + storage.js: feed in function objects from
// the Management API, get contract-shaped findings out. Zero live API needed
// in tests — the module is a pure classifier over the objects audit.js
// fetches.

// Build the Management API path for an edge function.
// Matches the path convention used by auth.js (e.g. /v1/projects/<ref>/config/auth).
export function fnApiPath(ref, fnId) {
  return `/v1/projects/${ref}/functions/${fnId}`;
}

// management_api_action: enable verify_jwt on a function.
function enableJwtAction(ref, fnId) {
  return {
    method: "PATCH",
    path: fnApiPath(ref, fnId),
    body: { verify_jwt: true },
  };
}

// management_api_action: disable wildcard CORS on a function.
function tightenCorsAction(ref, fnId) {
  return {
    method: "PATCH",
    path: fnApiPath(ref, fnId),
    body: { cors: false },
  };
}

// rollback_management_api_action: revert verify_jwt back to false (prior state).
function rollbackJwtAction(ref, fnId) {
  return {
    method: "PATCH",
    path: fnApiPath(ref, fnId),
    body: { verify_jwt: false },
  };
}

// rollback_management_api_action: revert cors back to true (prior state).
function rollbackCorsAction(ref, fnId) {
  return {
    method: "PATCH",
    path: fnApiPath(ref, fnId),
    body: { cors: true },
  };
}

// --- Body analysis (spec step 3: secret echo / unauthenticated writes) ---

// Patterns that indicate a function is READING a secret from the environment
// or the vault.
const SECRET_READ_PATTERNS = [
  /Deno\.env\.get\s*\(/i,
  /process\.env/i, // matches both process.env.X and process.env["X"]
  /Deno\.secrets/i,
];

// Patterns that indicate a function is LOGGING a value to the console,
// which could leak secrets if combined with secret reading.
const SECRET_ECHO_PATTERNS = [
  /console\.(log|error|warn|info|debug)\s*\(/i,
];

// Patterns that indicate a function performs WRITE operations on data.
const WRITE_PATTERNS = [
  /\.insert\s*\(/i,
  /\.update\s*\(/i,
  /\.delete\s*\(/i,
  /\.upsert\s*\(/i,
  /\binsert\s+into\s+/i,
  /\bupdate\s+\w+\s+set/i,
  /\bdelete\s+from\s+/i,
];

/**
 * Analyze a function body (source code string) for dangerous patterns.
 * @param {string} body — function source code
 * @returns {{ reading: boolean, echoing: boolean, writing: boolean } | null}
 *          null when body is not a string
 */
export function analyzeEdgeFunctionBody(body) {
  if (!body || typeof body !== "string") return null;
  return {
    reading: SECRET_READ_PATTERNS.some((p) => p.test(body)),
    echoing: SECRET_ECHO_PATTERNS.some((p) => p.test(body)),
    writing: WRITE_PATTERNS.some((p) => p.test(body)),
  };
}

// --- Per-function classification ---

/**
 * Classify a single edge function for security issues.
 *
 * @param {object} fn  — function object from the Management API:
 *   { id, name, slug, verify_jwt, cors, body?, status, import_map }
 * @param {string} [ref="unknown"] — project ref (for management_api_action paths)
 * @returns {Array} contract-shaped raw finding objects (normalizeFinding is called by audit.js)
 */
export function classifyEdgeFunction(fn, ref = "unknown") {
  if (!fn || typeof fn !== "object") return [];
  const fnId = fn.id || fn.slug || fn.name || "unknown";
  const name = fn.name || fn.slug || fn.id || "unknown";
  const findings = [];

  const bodyAnalysis = fn.body ? analyzeEdgeFunctionBody(fn.body) : null;

  // 1. verify_jwt=false → publicly invokable → HIGH
  //    Anyone can call this function with just the anon key (no user auth).
  if (fn.verify_jwt === false) {
    const evidence = {
      name,
      slug: fn.slug,
      verify_jwt: fn.verify_jwt,
      import_map: fn.import_map,
      status: fn.status,
    };
    if (bodyAnalysis) evidence.body_analysis = bodyAnalysis;

    findings.push({
      check: "edge_function_verify_jwt_disabled",
      category: "coverage-edge-functions",
      severity: "high",
      confidence: "confirmed", // verify_jwt is a hard config value from the API
      target: `function:${fnId}`,
      evidence,
      fix: {
        sql: [],
        rollback_sql: [],
        dashboard_action: null,
        management_api_action: enableJwtAction(ref, fnId),
        rollback_management_api_action: rollbackJwtAction(ref, fnId),
        requires_service_role: false,
      },
    });
  }

  // 2. Wildcard CORS → MEDIUM
  //    When CORS is enabled (cors: true), the function sends
  //    Access-Control-Allow-Origin: *, letting ANY web origin call it.
  if (fn.cors === true || fn.cors === "wildcard" || fn.cors === "*") {
    findings.push({
      check: "edge_function_wildcard_cors",
      category: "coverage-edge-functions",
      severity: "medium",
      confidence: "confirmed",
      target: `function:${fnId}`,
      evidence: {
        name,
        slug: fn.slug,
        cors: fn.cors,
        verify_jwt: fn.verify_jwt,
      },
      fix: {
        sql: [],
        rollback_sql: [],
        dashboard_action:
          "Dashboard -> Edge Functions -> [function] -> Configuration: set specific allowed origins instead of wildcard",
        management_api_action: tightenCorsAction(ref, fnId),
        rollback_management_api_action: rollbackCorsAction(ref, fnId),
        requires_service_role: false,
      },
    });
  }

  // 3. Secret echo: function reads secrets from env/vault AND logs/returns them
  //    → HIGH (potential secret leak to any caller or via logs)
  if (bodyAnalysis && bodyAnalysis.reading && bodyAnalysis.echoing) {
    findings.push({
      check: "edge_function_secret_echo",
      category: "coverage-edge-functions",
      severity: "high",
      confidence: "inferred", // code-pattern based, not actively probed
      target: `function:${fnId}`,
      evidence: {
        name,
        slug: fn.slug,
        body_analysis: bodyAnalysis,
        reason:
          "Function reads secrets (Deno.env.get / process.env / Deno.secrets) and logs or returns them to the caller",
      },
      fix: {
        sql: [],
        rollback_sql: [],
        dashboard_action: null,
        management_api_action: enableJwtAction(ref, fnId),
        rollback_management_api_action: rollbackJwtAction(ref, fnId),
        requires_service_role: false,
      },
    });
  }

  // 4. Unauthenticated write: verify_jwt=false AND the body performs write
  //    operations (insert/update/delete/upsert) → CRITICAL
  //    Anyone can anonymously mutate data.
  if (fn.verify_jwt === false && bodyAnalysis && bodyAnalysis.writing) {
    findings.push({
      check: "edge_function_unauthenticated_write",
      category: "coverage-edge-functions",
      severity: "critical",
      confidence: "inferred",
      target: `function:${fnId}`,
      evidence: {
        name,
        slug: fn.slug,
        verify_jwt: fn.verify_jwt,
        body_analysis: bodyAnalysis,
        reason:
          "Publicly invokable function (verify_jwt=false) performs write operations (insert/update/delete/upsert) — anonymous callers can mutate data",
      },
      fix: {
        sql: [],
        rollback_sql: [],
        dashboard_action: null,
        management_api_action: enableJwtAction(ref, fnId),
        rollback_management_api_action: rollbackJwtAction(ref, fnId),
        requires_service_role: false,
      },
    });
  }

  return findings;
}

/**
 * Process every edge function into findings via classifyEdgeFunction().
 *
 * @param {Array} functions — function objects from the Management API
 * @param {string} ref — project ref
 * @returns {Array} raw finding objects
 */
export function processEdgeFunctions(functions, ref = "unknown") {
  const findings = [];
  if (!Array.isArray(functions)) return findings;
  for (const fn of functions) {
    const fnFindings = classifyEdgeFunction(fn, ref);
    for (const f of fnFindings) findings.push(f);
  }
  return findings;
}
