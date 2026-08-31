// RPC exposure classifier + active-probe driver (pure, DB-free, unit-testable).
// Mirrors scripts/checks/rls.js: inject probeFn so tests stub the transport
// with a fake async function — zero live DB / no global.fetch mocking needed.
//
// Spec coverage:
//  - entry 8 (coverage-rpc enumerate): callers feed in rows from pg_proc for
//    EVERY anon/authenticated-EXECUTE function (SECURITY DEFINER AND INVOKER),
//    with prosecdef / provolatile / return_type / arg signature / proconfig.
//    The DB is the source of truth (not discover.js repo-parse).
//  - entry 9 (coverage-rpc active probe): POST /rest/v1/rpc/<fn> with a SAFE
//    no-op payload; classify 42501(blocked) vs business-error vs 200/204;
//    confidence 'confirmed' (body executed) vs 'inferred' (grant-only/gated);
//    split confirmed-executable vs merely-granted so granted-but-gated fns
//    (the 96-flag over-count) are NOT counted as confirmed.

const NIL_UUID = "00000000-0000-0000-0000-000000000000";

const ZERO_BY_TYPE = new Map([
  ["uuid", NIL_UUID],
  ["guid", NIL_UUID],
]);

// SQLSTATEs raised INSIDE the RPC body = the function executed as anon and hit a
// data/logic exception before any auth gate (spec: P0001/P0002/22023/23502/23503,
// plus common data exceptions that imply the same — i.e. business logic ran).
const BUSINESS_ERRORS = new Set([
  "P0001", "P0002", "P0003", "22023",
  "22001", "22007", "22018",
  "23502", "23503", "23505", "23506", "23507",
]);

// Build a safe, no-op JSON payload for an RPC call from its arg signature so the
// call cannot mutate real data. IN/INOUT args -> null (or a nil UUID for uuid
// typed args so NOT NULL checks don't error); VARIADIC args -> []; OUT/TABLE
// args are excluded (never sent to PostgREST).
export function buildSafePayload(fn) {
  const args = fn.args || [];
  const payload = Object.create(null);
  for (const a of args) {
    if (!a || !a.name) continue;
    const mode = (a.mode || "i").toLowerCase();
    if (mode === "o" || mode === "t") continue; // OUT / TABLE args are not sent
    if (mode === "v") {
      payload[a.name] = [];
      continue;
    }
    const t = (a.type || "").toLowerCase();
    if (ZERO_BY_TYPE.has(t)) payload[a.name] = ZERO_BY_TYPE.get(t);
    else payload[a.name] = null;
  }
  return payload;
}

// Parse a pg_get_function_arguments() signature string ("a uuid, b text, ...")
// into [{name,type,mode:'i'}]. Pure; used by the audit.js wiring to turn the DB
// string into structured args for buildSafePayload. Handles type modifiers that
// contain commas (e.g. numeric(10,2)) via paren-depth-aware splitting.
export function parseArgSignature(sig) {
  if (!sig) return [];
  const parts = [];
  let depth = 0;
  let cur = "";
  for (const ch of sig) {
    if (ch === "(") depth++;
    else if (ch === ")") depth--;
    if (ch === "," && depth === 0) {
      parts.push(cur.trim());
      cur = "";
      continue;
    }
    cur += ch;
  }
  if (cur.trim()) parts.push(cur.trim());
  return parts.map((p, i) => {
    const sp = p.indexOf(" ");
    if (sp <= 0) return { name: `arg${i + 1}`, type: p, mode: "i" };
    return { name: p.slice(0, sp).trim(), type: p.slice(sp).trim(), mode: "i" };
  });
}

// Pull the SQLSTATE code out of a PostgREST error body, if present.
// PostgREST errors: {"code":"23502","details":"...","hint":"...","message":"..."}.
function extractSqlstate(body) {
  if (!body) return null;
  try {
    const j = JSON.parse(body);
    if (j && typeof j.code === "string") return j.code.toUpperCase();
    if (j && Array.isArray(j)) {
      for (const e of j) if (e && typeof e.code === "string") return e.code.toUpperCase();
    }
  } catch {
    /* not JSON */
  }
  // Fallback: scan raw text for a bare 5-char SQLSTATE token.
  const m = String(body).match(/[0-9A-Z]{5}/);
  return m ? m[0] : null;
}

// Classify a single RPC probe result.
// probe: { status, body } | null  (null => grant-only, not probed)
// returns: { exploited, confirmed, confidence, blocked, reason, status }
export function classifyRpc(fn, probe) {
  if (!probe) {
    return {
      exploited: false,
      confirmed: false,
      confidence: "inferred",
      blocked: false,
      reason: "not probed (grant-only)",
      status: null,
    };
  }
  const status = probe.status;

  if (status === 200 || status === 204) {
    return { exploited: true, confirmed: true, confidence: "confirmed", blocked: false, reason: `HTTP ${status} (executed)`, status };
  }
  // Auth gate rejections: granted but the call was refused before business logic.
  if (status === 42501 || status === 401 || status === 403) {
    return { exploited: false, confirmed: false, confidence: "inferred", blocked: true, reason: `HTTP ${status} (gated/blocked)`, status };
  }
  // Business/data exception inside the body => body executed, no auth gate.
  const sqlstate = extractSqlstate(probe.body);
  if (sqlstate && BUSINESS_ERRORS.has(sqlstate)) {
    return { exploited: true, confirmed: true, confidence: "confirmed", blocked: false, reason: `business-error ${sqlstate} (body executed, no auth gate)`, status };
  }
  // Not exposed at all (shouldn't happen for enumerated fns, but handle defensively).
  if (status === 404) {
    return { exploited: false, confirmed: false, confidence: "inferred", blocked: true, reason: "404 not exposed", status };
  }
  return { exploited: false, confirmed: false, confidence: "inferred", blocked: false, reason: `HTTP ${status} (not executed/confirmed)`, status };
}

// Severity for one RPC finding.
function severityFor(fn, cls) {
  if (cls.confirmed) {
    if (fn.prosecdef) return "critical"; // runs as owner -> anon-escalation
    return "high";
  }
  return "low"; // inferred / granted-but-gated -> info-level
}

// Build the arg-type signature for a function (e.g. "uuid, text") suitable for
// PostgreSQL REVOKE/GRANT ON FUNCTION statements. Excludes OUT/TABLE args.
function fnArgTypes(fn) {
  const args = fn.args || [];
  const types = [];
  for (const a of args) {
    const mode = (a && a.mode) || "i";
    if (mode === "o" || mode === "t") continue;
    types.push(a.type || "text");
  }
  return types.join(", ");
}

// Build the finding object for one function + its probe classification.
// fn: { function_name, prosecdef, provolatile, return_type, anon_execute,
//       auth_execute, config, args:[{name,type,mode}] }
function buildFinding(fn, payload, cls) {
  const exploited = cls.exploited;
  return {
    check: exploited ? "rpc_confirmed_executable" : "rpc_granted_inferred",
    category: "coverage-rpc",
    severity: severityFor(fn, cls),
    confidence: cls.confidence,
    target: fn.function_name,
    evidence: {
      prosecdef: fn.prosecdef,
      provolatile: fn.provolatile,
      return_type: fn.return_type,
      anon_execute: fn.anon_execute,
      auth_execute: fn.auth_execute,
      arg_signature: (fn.args || []).map((a) => `${a.name || "?"} ${a.type || ""}`).join(", "),
      payload,
      probe: cls.status != null ? { status: cls.status, reason: cls.reason } : undefined,
    },
    exploitable_without_auth: exploited,
    fix: {
      sql: [`REVOKE EXECUTE ON FUNCTION ${fn.schema_name || "public"}.${fn.function_name}(${fnArgTypes(fn)}) FROM anon;`],
      rollback_sql: [`GRANT EXECUTE ON FUNCTION ${fn.schema_name || "public"}.${fn.function_name}(${fnArgTypes(fn)}) TO anon;`],
      requires_service_role: false,
    },
  };
}

// Orchestrator: actively probe each anon-executable RPC and classify exposure.
// functions: [{ function_name, prosecdef, provolatile, return_type,
//               anon_execute, auth_execute, config, args:[{name,type,mode}] }]
// probeFn: async (fnName, payload) => { status, body }   (stub in tests; in audit.js
//          it POSTs to /rest/v1/rpc/<fn> with the anon key)
// probeVolatile: if true, also probe provolatile='v' functions (risky — they
//          execute real side-effects per call). Default false — volatile fns
//          are reported as inferred-only (grant present, not execution-confirmed).
// returns: { findings: [...], confirmed_count, inferred_count }
export async function probeRpcs(functions, probeFn, probeVolatile = false) {
  const findings = [];
  let confirmed_count = 0;
  let inferred_count = 0;

  // Probe anon-executable functions concurrently (bounded pool) to avoid
  // serial per-function round-trips on projects with 100+ RPC (a real project
  // we tested had 287 functions). Spec entry 6 scaling fix.
  const PROBE_CONCURRENCY = 8;
  // Volatile functions are NOT probed unless --probe-volatile is explicitly
  // passed. A volatile function with zero args cannot be made safe — its body
  // runs for real on every call, potentially with side effects. Still REPORTED
  // (downgraded to inferred), we just lose the live confirmation.
  const exeFns = functions.filter((fn) => fn.anon_execute && (probeVolatile || fn.provolatile !== "v"));

  // Phase 1: probe all anon-executable functions concurrently (bounded pool).
  const probeData = new Array(functions.length).fill(null);
  for (let ci = 0; ci < exeFns.length; ci += PROBE_CONCURRENCY) {
    const chunk = exeFns.slice(ci, ci + PROBE_CONCURRENCY);
    await Promise.all(
      chunk.map(async (fn) => {
        const payload = buildSafePayload(fn);
        if (probeFn) {
          probeData[functions.indexOf(fn)] = await probeFn(fn.function_name, payload);
        }
      })
    );
  }

  // Phase 2: classify all functions (sync after probes resolve).
  for (const fn of functions) {
    const idx = functions.indexOf(fn);
    if (!fn.anon_execute) continue; // entry 9 probes ANON-executable functions
    const payload = buildSafePayload(fn);
    const probe = probeData[idx];
    const cls = classifyRpc(fn, probe);
    findings.push(buildFinding(fn, payload, cls));
    if (cls.confirmed) confirmed_count++;
    else inferred_count++;
  }
  return { findings, confirmed_count, inferred_count };
}
