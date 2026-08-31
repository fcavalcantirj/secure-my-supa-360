#!/usr/bin/env node
// Supabase Security Auditor — pure Node.js, no deps.
//
// Output: JSON findings to stdout (default) or HTML file.
// Exit codes: 0=clean, 2=findings found, 10=auth error, 11=network error,
//             12=schema validation failure of own output.
//
// Usage:
//   SUPABASE_ACCESS_TOKEN=sbp_xxx node audit.js <project-ref> [--json] [--html report.html] [--probe] [--probe-volatile] [--history] [--fail-on high] [--confirmed-only] [--baseline baseline.json]
//   node audit.js <project-ref> --token sbp_xxx --json
//   node audit.js <project-ref> --token sbp_xxx --html report.html
//   node audit.js --discover [path]
//
// JSON output follows schema/finding.schema.json (contract v1.0).

import { writeFileSync, readFileSync } from "node:fs";
import { createInterface } from "node:readline";
import { processTables } from "./checks/rls.js";
import { processRlsPerf } from "./checks/rls_perf.js";
import { processHistoricalAccess } from "./checks/history.js";
import { probeRpcs, parseArgSignature } from "./checks/rpc.js";
import { analyzeFunctionBodies } from "./checks/function-body.js";
import { processViews } from "./checks/views.js";
import { processStorage, findBucketConfigIssues } from "./checks/storage.js";
import { analyzeAuthConfig } from "./checks/auth.js";
import { processColumnGrants, findExposedSchemas } from "./checks/grants.js";
import { scanForSensitiveColumns } from "./checks/pii.js";
import { processEdgeFunctions } from "./checks/edge_functions.js";
import { processNetworkDb } from "./checks/network_db.js";
import { processExtensionsCron } from "./checks/extensions_cron.js";
import { processRealtime } from "./checks/realtime.js";
import { processDataApi } from "./checks/data_api.js";
import { classifyDefaultAcls } from "./checks/default_privileges.js";
import {
  normalizeFinding,
  sortFindings,
  buildSummary,
  scanForSecrets,
  computeExitCode,
  classifyError,
  EXIT_CODES,
  SEVERITY_RANK,
} from "./contract.js";
import { validate } from "./validate.js";
import { loadSuppressions, applySuppressions, checkStaleSuppressions, suppressionSummary } from "./suppress.js";
import {
  loadBaseline,
  baselineExists,
  saveBaseline,
  diffBaseline,
  buildBaselineDiff,
  computeBaselineExitCode,
} from "./baseline.js";

const API = "https://api.supabase.com/v1";
const SCHEMA = JSON.parse(
  readFileSync(new URL("../schema/finding.schema.json", import.meta.url), "utf8")
);

const SEVERITY_ORDER = SEVERITY_RANK;

// AbortController signal for --timeout. When set, all fetch calls in sql()
// and probe functions will abort when the deadline fires, preventing infinite
// runs on large projects (spec entry 6 scaling fix).
let _timeoutSignal = null;
// Track the probe user JWT so we can delete it in main()'s finally block.
// The probe user is a REAL account created via /auth/v1/signup — it MUST be
// cleaned up after the run to avoid leaving orphan accounts in auth.users.
let _probeUserJwt = null;
let _probeUserRef = null;
export function setTimeoutSignal(seconds) {
  if (seconds > 0) {
    const controller = new AbortController();
    _timeoutSignal = controller.signal;
    setTimeout(() => controller.abort(), seconds * 1000);
    return controller;
  }
  _timeoutSignal = null;
  return null;
}

const CHECKS = {
  rls_disabled: {
    severity: "critical",
    category: "coverage-rls",
    title: "RLS disabled on table accessible via anon",
    explain: "Without RLS, anon role with default CRUD grants can read/insert/delete any row.",
  },
  rls_no_policies_with_anon_grants: {
    severity: "low",
    category: "coverage-rls",
    title: "RLS-locked table still has direct anon grants (defense-in-depth)",
    explain: "Currently safe — RLS blocks all access. But if RLS is ever disabled by mistake, data leaks instantly. Best practice: revoke grants too.",
  },
  rls_permissive_policy: {
    severity: "high",
    category: "coverage-rls",
    title: "RLS enabled but policy does not scope to the caller (USING true / no tenant check)",
    explain: "RLS is on, but the policy allows everyone or doesn't reference auth.uid()/a tenant column. The original tool only looked at RLS off vs zero policies and MISSED this (RLS-ON + USING(true) policy + anon grants is a direct read leak). With anon/auth grants this is a confirmed leak; a live probe upgrades confidence to 'confirmed'.",
  },
  rls_permissive_write_policy: {
    severity: "high",
    category: "coverage-rls",
    title: "RLS policy with permissive/missing write guard (INSERT/UPDATE WITHOUT CHECK)",
    explain: "An INSERT/UPDATE/ALL policy reachable by anon has a WITH CHECK that is permissive (true), missing (NULL), or does not scope to the caller. This lets anon insert/tamper arbitrary rows — a write-side leak the original tool never checked.",
  },
  rls_with_check_divergence: {
    severity: "medium",
    category: "coverage-rls",
    title: "RLS USING and WITH CHECK diverge on UPDATE/ALL (write-only scope)",
    explain: "The policy's USING (row scope) and WITH CHECK (value scope) differ, so a caller-scoped read can hide a broader write scope — a write-only tampering / IDOR-on-write risk.",
  },
  function_security_definer_anon_executable: {
    severity: "high",
    category: "coverage-rpc",
    title: "SECURITY DEFINER function executable by anon",
    explain: "Function runs with creator privileges. If buggy, escalates to admin.",
  },
  default_privileges_not_revoked: {
    severity: "medium",
    category: "coverage-rls",
    title: "Default privileges not revoked from anon/authenticated",
    explain: "New tables you create will be auto-exposed. Supabase enforces this by Oct 30, 2026.",
  },
  storage_bucket_public: {
    severity: "high",
    category: "coverage-storage",
    title: "Storage bucket is public",
    explain: "Anyone can list and download all files in the bucket.",
  },
  storage_bucket_misconfigured: {
    severity: "medium",
    category: "coverage-storage",
    title: "Storage bucket missing file size limit or MIME type restrictions",
    explain: "Bucket has no file_size_limit or allowed_mime_types set (or a wildcard '*/*'). Without limits, uploaders can fill the bucket with arbitrarily large or dangerous file types.",
  },
  storage_objects_anon_read: {
    severity: "high",
    category: "coverage-storage",
    title: "Anonymous SELECT on storage.objects (object read leak)",
    explain: "An anonymous/public SELECT policy on storage.objects lets unauthenticated callers list and download objects. A live probe that returns rows upgrades this to 'confirmed'; on buckets holding PII the severity escalates to critical.",
  },
  storage_objects_anon_insert: {
    severity: "critical",
    category: "coverage-storage",
    title: "Anonymous INSERT on storage.objects (arbitrary upload)",
    explain: "An anonymous INSERT policy on storage.objects lets anyone upload arbitrary files — the anon-upload gap. Confirmed when the upload probe returns 200/201.",
  },
  storage_objects_anon_tamper: {
    severity: "critical",
    category: "coverage-storage",
    title: "Anonymous UPDATE/DELETE on storage.objects (tamper / wipe)",
    explain: "An anonymous UPDATE/DELETE policy on storage.objects lets anyone mutate or wipe stored objects — the anon-delete gap. Confirmed when the delete probe is authorized.",
  },
  storage_policy_unscoped_path: {
    severity: "medium",
    category: "coverage-storage",
    title: "Storage policy lacks path/foldername scoping",
    explain: "The anon-granting storage.objects policy has no storage.foldername()/path_tokens/name LIKE guard, so the whole bucket (not just intended paths) is exposed.",
  },
  auth_signups_enabled_no_confirm: {
    severity: "medium",
    category: "coverage-auth",
    title: "Signups enabled without email confirmation",
    explain: "Anyone can create accounts and bypass email-gated logic.",
  },
  realtime_publication_no_rls: {
    severity: "critical",
    category: "coverage-realtime",
    title: "Table in supabase_realtime publication WITHOUT RLS",
    explain: "Realtime sends row changes over WebSockets to anyone subscribed with the anon key. RLS policies are checked, but with RLS disabled there's nothing to check. Every INSERT/UPDATE is broadcast.",
  },
  realtime_broadcast_anon_read: {
    severity: "high",
    category: "coverage-realtime",
    title: "Anon can read realtime.messages (broadcast/presence readable)",
    explain: "The realtime.messages table is readable by anon without policy restrictions. Anyone can listen to broadcast and presence messages from all channels.",
  },
  realtime_broadcast_anon_write: {
    severity: "critical",
    category: "coverage-realtime",
    title: "Anon can write realtime.messages (anonymous broadcast)",
    explain: "The realtime.messages table is INSERTable by anon without policy restrictions. Anyone can broadcast messages to all channels, enabling spam, phishing, or data injection via realtime.",
  },
  anonymous_signins_enabled: {
    severity: "high",
    category: "coverage-auth",
    title: "Anonymous sign-ins enabled",
    explain: "Anyone can become an 'authenticated' user without email verification. Defeats `auth.uid() IS NOT NULL` style RLS policies.",
  },
  weak_password_policy: {
    severity: "medium",
    category: "coverage-auth",
    title: "Weak password policy",
    explain: "Minimum length below 8 characters. Use at least 8 + complexity requirements (digits/symbols).",
  },
  no_captcha_on_auth: {
    severity: "medium",
    category: "coverage-auth",
    title: "No CAPTCHA on auth endpoints",
    explain: "Without CAPTCHA, signup/login forms can be brute-forced or spammed by bots.",
  },
  auth_hibp_disabled: {
    severity: "medium",
    category: "coverage-auth",
    title: "HIBP password breach checking disabled",
    explain: "Compromised passwords (known via haveibeenpwned) are not blocked, allowing credential-stuffing with breached passwords.",
  },
  auth_mfa_disabled: {
    severity: "high",
    category: "coverage-auth",
    title: "MFA not enforced",
    explain: "Multi-factor authentication is not required. Account takeover via stolen passwords is trivial.",
  },
  auth_jwt_exp_too_long: {
    severity: "medium",
    category: "coverage-auth",
    title: "JWT expiration too long",
    explain: "JWT tokens survive for an extended window, increasing the impact of token theft / replay.",
  },
  auth_redirect_allowlist_open: {
    severity: "high",
    category: "coverage-auth",
    title: "Open redirect allowlist",
    explain: "The URI allowlist is empty, allowing auth-code interception via arbitrary redirect URIs.",
  },
  auth_rate_limit_missing: {
    severity: "medium",
    category: "coverage-auth",
    title: "Missing rate limits on auth endpoints",
    explain: "Auth endpoints lack rate limiting, enabling brute-force and enumeration attacks.",
  },
  function_no_search_path: {
    severity: "medium",
    category: "coverage-rpc",
    title: "SECURITY DEFINER function without SET search_path",
    explain: "Function with mutable search_path can be hijacked: an attacker with CREATE on any schema in the path can shadow built-in functions and run arbitrary code as the function owner.",
  },
  function_secdef_missing_auth_check: {
    severity: "critical",
    category: "coverage-rpc",
    title: "SECURITY DEFINER function has no internal auth check",
    explain: "Function runs as the owner. If anon/auth-executable and contains no auth.uid()/auth.role()/current_setting check, any anon caller can trigger owner-privileged logic (data exfiltration, money transfer, etc.).",
  },
  function_secdef_no_search_path: {
    severity: "medium",
    category: "coverage-rpc",
    title: "SECURITY DEFINER function without SET search_path (search_path injection)",
    explain: "A secdef function with a mutable search_path can be hijacked: an attacker with CREATE on a schema earlier in the path can shadow built-in functions and run arbitrary code as the function owner.",
  },
  function_secdef_dynamic_sql: {
    severity: "high",
    category: "coverage-rpc",
    title: "SECURITY DEFINER function uses unsafe dynamic SQL",
    explain: "EXECUTE without USING or format() with %s interpolation in a secdef function allows SQL injection: arguments are concatenated into the query string unquoted.",
  },
  view_security_definer_bypass: {
    severity: "high",
    category: "coverage-views",
    title: "View runs as SECURITY DEFINER (bypasses base-table RLS)",
    explain: "A view with security_invoker=false executes as the view owner. If reachable by anon, it can return rows from an RLS-locked base table that anon would otherwise be blocked from. A live probe of 200+rows confirms the bypass.",
  },
  view_exposes_pii_to_anon: {
    severity: "critical",
    category: "coverage-views",
    title: "View exposes PII columns to anonymous callers",
    explain: "An anonymous-SELECTable view includes sensitive columns (cpf, email, phone, etc.). Even with security_invoker=true, the view definition leaks PII by construction.",
  },
  rpc_confirmed_executable: {
    severity: "high",
    category: "coverage-rpc",
    title: "RPC function executes for anonymous callers (active probe confirmed)",
    explain: "Anonymous POST to /rest/v1/rpc/<fn> actually ran the function body. If SECURITY DEFINER this ran as the owner (anon-escalation); otherwise it ran as anon and leaked/acted on data.",
  },
  rpc_granted_inferred: {
    severity: "low",
    category: "coverage-rpc",
    title: "RPC function granted to anon but not confirmed exploitable (inferred)",
    explain: "Anonymous EXECUTE grant exists but the active probe was blocked/gated (42501/401/403/404). Not exploitable now, but grant-only inference — revoke if unused.",
  },
  column_grant_exposes_column: {
    severity: "critical",
    category: "coverage-schema-grants",
    title: "Column-level SELECT grant exposes a column to anon/authenticated",
    explain: "A column-level SELECT grant on a specific column lets anon/authenticated read that column even when table-level SELECT is revoked (the column-grant bypass). Sensitive columns (PII/credentials) always escalate to critical.",
  },
  custom_schema_exposed: {
    severity: "low",
    category: "coverage-schema-grants",
    title: "Custom schema exposed via PostgREST db_schema config",
    explain: "A non-standard schema is in the PostgREST db_schema config, making its tables/views/API routes reachable by anon. Remove it from 'Exposed schemas' in Dashboard -> Project Settings -> Data API unless intentionally required.",
  },
  edge_function_verify_jwt_disabled: {
    severity: "high",
    category: "coverage-edge-functions",
    title: "Edge Function has verify_jwt disabled (publicly invokable)",
    explain: "The function can be called by anyone with the anon key — no user authentication is checked. If the function performs privileged operations, anon callers can trigger them. Set verify_jwt=true to require a valid JWT.",
  },
  edge_function_wildcard_cors: {
    severity: "medium",
    category: "coverage-edge-functions",
    title: "Edge Function has wildcard CORS enabled",
    explain: "The function sends Access-Control-Allow-Origin: *, allowing any web origin to call it from a browser. Restrict to known origins.",
  },
  edge_function_secret_echo: {
    severity: "high",
    category: "coverage-edge-functions",
    title: "Edge Function reads secrets and logs/returns them",
    explain: "The function body reads secrets from the environment (Deno.env.get / process.env / Deno.secrets) and passes them to console.log or returns them to the caller. This can leak secrets to logs or anonymous clients.",
  },
  edge_function_unauthenticated_write: {
    severity: "critical",
    category: "coverage-edge-functions",
    title: "Edge Function accepts unauthenticated writes",
    explain: "The function has verify_jwt disabled and performs write operations (insert/update/delete/upsert). Anonymous callers can mutate data through this function.",
  },
  db_no_network_restrictions: {
    severity: "medium",
    category: "coverage-network-db",
    title: "Direct Postgres (5432) reachable without IP allowlist",
    explain: "Network restrictions are not enabled, so the Postgres instance is directly reachable from any IP on port 5432. On production projects this is critical — use the Supabase Connection Pooler or VPN instead.",
  },
  db_ssl_disabled: {
    severity: "medium",
    category: "coverage-network-db",
    title: "SSL/TLS not enforced for Postgres connections",
    explain: "The project does not enforce SSL for direct Postgres connections, allowing credentials and data to traverse the network in cleartext. Enable SSL and use the connection pooler.",
  },
  db_pool_session_mode: {
    severity: "low",
    category: "coverage-network-db",
    title: "Connection pooler in 'session' mode (incompatible with serverless)",
    explain: "The Supabase connection pooler is in 'session' mode, which does not work well with serverless functions that scale to zero (connection exhaustion). Switch to 'transaction' mode.",
  },
  extension_risky_installed: {
    severity: "medium",
    category: "coverage-extensions-cron",
    title: "Risky extension installed (http / pg_net) reachable by low-priv roles",
    explain: "The extension allows outbound HTTP/network calls from the database (SSRF, data exfiltration). Anon/authenticated callable functions can pivot to internal services.",
  },
  extension_known_vulnerable: {
    severity: "high",
    category: "coverage-extensions-cron",
    title: "Extension installed at a known-vulnerable version",
    explain: "The extension version has known CVEs. Update to a patched version.",
  },
  cron_job_embedded_secret: {
    severity: "high",
    category: "coverage-extensions-cron",
    title: "pg_cron job command contains an embedded secret",
    explain: "A scheduled pg_cron job has a secret (bearer token, PAT, API key, DB connection string) embedded in its command. Store secrets in vault.get_secret() instead.",
  },
  vault_decrypted_secrets_exposed: {
    severity: "critical",
    category: "coverage-extensions-cron",
    title: "vault.decrypted_secrets readable by anon/authenticated",
    explain: "The vault.decrypted_secrets table is SELECTable by anon or authenticated roles. This exposes all stored secrets in cleartext to untrusted callers.",
  },
  data_api_auto_expose_on: {
    severity: "medium",
    category: "coverage-data-api",
    title: "Data API auto-expose ON — new tables exposed to anon",
    explain: "The 'Automatically expose new tables' toggle is ON (default privileges grant anon/authenticated access). Every new table created in the public schema is immediately readable/writable via the REST API without explicit grants.",
  },
  data_api_many_functions_exposed: {
    severity: "low",
    category: "coverage-data-api",
    title: "Large anon-executable RPC surface exposed via REST",
    explain: "Many RPC functions are executable by anon/authenticated roles via the REST API. A large RPC surface increases the attack area for SQL injection and SECURITY DEFINER escalation.",
  },
  data_api_disabled: {
    severity: "info",
    category: "coverage-data-api",
    title: "Data API is disabled (db_schema empty) — REST/SQL surface is off",
    explain: "PostgREST db_schema is empty, meaning the Supabase Data API (REST) is not exposing any schemas. This is the secure-by-default state. No tables are reachable via /rest/v1/ with the anon key.",
  },
  rls_unwrapped_auth_fn: {
    severity: "medium",
    category: "rls-performance",
    title: "RLS policy calls auth.uid()/auth.jwt()/current_setting() unwrapped (per-row execution)",
    explain: "An auth function called unwrapped in a policy expression re-executes on every row, defeating the Postgres initPlan cache. Wrapping it in (select auth.uid()) makes it a cached scalar subselect.",
  },
  rls_unindexed_policy_column: {
    severity: "medium",
    category: "rls-performance",
    title: "RLS policy references a column with no btree index (slow per-row predicate)",
    explain: "A policy column used in an equality predicate against an auth value has no leading btree index. This forces a sequential scan per predicate evaluation — up to 100x slower on large tables.",
  },
  rls_policy_join: {
    severity: "medium",
    category: "rls-performance",
    title: "RLS policy contains a join or correlated subquery (per-row execution)",
    explain: "A policy with EXISTS(SELECT ... FROM <table>) or a correlated IN (SELECT ...) re-executes the subquery for every row, against varying join data. Encapsulate in a SECURITY DEFINER helper or reverse the join to a non-correlated form.",
  },
  rls_policy_public_role: {
    severity: "low",
    category: "rls-performance",
    title: "RLS policy grants role 'public' (forces anon pre-evaluation)",
    explain: "A policy with roles = {public} makes Postgres evaluate the policy for the anon role before rejection. Scoping to authenticated filters unauthorized users first.",
  },
};

const UA = "supabase-security/0.4";

// --trace flag: logs every Management-API query, HTTP status, and probe
// request/response to stderr. Never logs tokens or secrets.
let _trace = false;
export function setTrace(enabled) { _trace = enabled; }

// Redact the token from trace output
function _redactQuery(query) {
  return query.replace(/\s+/g, " ").slice(0, 200);
}

// Error types for graceful exit-code mapping
class AuthError extends Error {
  constructor(message) {
    super(message);
    this.name = "AuthError";
  }
}

// --- Scale helpers (Bug 4 fix) ---

// Batch size for id-batched SQL queries. Heavy queries with correlated
// subqueries (PII json_agg x N tables, pg_get_functiondef x N functions) time
// out (SQL 544 statement timeout) on large schemas. sqlBatched() first fetches
// a cheap oid list, then fetches details in batches of SQL_BATCH_SIZE objects
// via WHERE oid = ANY(ARRAY[...]) — guaranteeing each heavy query touches
// exactly that many objects, NOT an OFFSET re-scan.
const SQL_BATCH_SIZE = 25;

// Maximum retry attempts for HTTP 429 (rate-limit) from the Supabase Management
// API. Short exponential backoff keeps total wait bounded.
const SQL_MAX_RETRIES = 3;
const SQL_RETRY_BASE_MS = 500;

function _delay(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// Run a SQL query via the Supabase Management API, retrying on 429 (rate limit)
// with short backoff. AuthError (401/403) throws immediately — retrying won't
// help and aborts the entire audit. All other HTTP errors also throw immediately
// (they indicate real problems, not transient rate limiting). Aborts via
// _timeoutSignal if the global deadline fires.
async function sql(token, ref, query) {
  // Tag ALL audit SQL with /* supa360-probe */ so history.js can exclude
  // these queries from historical analysis. Our own audit queries must never
  // be mistaken for attacker activity. (Solvr #163: previously only the
  // history query was tagged — now every sql() call is.)
  const tagged = `/* supa360-probe */ ${query}`;
  if (_trace) console.error(`[trace] SQL QUERY: ${_redactQuery(tagged)}`);
  for (let attempt = 0; attempt <= SQL_MAX_RETRIES; attempt++) {
    const r = await fetch(`${API}/projects/${ref}/database/query`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
        "User-Agent": UA,
      },
      body: JSON.stringify({ query: tagged }),
      signal: _timeoutSignal,
    });
    if (_trace) console.error(`[trace] SQL STATUS: ${r.status}`);
    if (r.status === 429 && attempt < SQL_MAX_RETRIES) {
      // Rate limited — back off and retry this query.
      const backoff = SQL_RETRY_BASE_MS * Math.pow(2, attempt);
      if (_trace) console.error(`[trace] SQL 429 — backing off ${backoff}ms (attempt ${attempt + 1}/${SQL_MAX_RETRIES})`);
      await _delay(backoff);
      continue;
    }
    if (!r.ok) {
      if (r.status === 401 || r.status === 403) {
        throw new AuthError(`SQL ${r.status}: ${(await r.text()).slice(0, 200)}`);
      }
      throw new Error(`SQL ${r.status}: ${(await r.text()).slice(0, 200)}`);
    }
    return await r.json();
  }
}

// Run a list+detail pair in oid batches to avoid SQL 544 statement timeouts on
// large schemas. `listQuery` must be cheap (no correlated subqueries) and
// return one row per object with an `oid` column. `detailQuery` is the heavy
// query containing the literal placeholder `__OID_BATCH__` which is replaced
// with `ARRAY[n,n,n,...]` for each batch — guaranteeing each heavy query touches
// exactly `batchSize` objects, NOT an OFFSET re-scan. Oids are validated as
// safe integers to prevent injection. Aborts transparently if _timeoutSignal
// fires (the AbortError propagates to the caller's try/catch).
//
// `_sqlFn` is injected for unit testing (defaults to the module's `sql()`).
export async function sqlBatched(token, ref, listQuery, detailQuery, batchSize = SQL_BATCH_SIZE, _sqlFn = sql) {
  const listRows = await _sqlFn(token, ref, listQuery);
  if (!listRows || listRows.length === 0) return [];

  const all = [];
  for (let i = 0; i < listRows.length; i += batchSize) {
    const batch = listRows.slice(i, i + batchSize);
    const oids = [...new Set(batch
      .map((r) => Number(r.oid))
      .filter((n) => Number.isSafeInteger(n)))];
    if (oids.length === 0) continue;
    const oidList = `ARRAY[${oids.join(",")}]`;
    const pagedQuery = detailQuery.replace("__OID_BATCH__", oidList);
    const rows = await _sqlFn(token, ref, pagedQuery);
    if (rows && rows.length > 0) all.push(...rows);
  }
  return all;
}

// Bounded concurrency pool: runs async tasks two at a time-ish, never more than
// `concurrency` executing simultaneously. Preserves result order. Used to
// parallelize independent check sections so a slow one does not block the rest.
export function boundedPool(tasks, concurrency = 6) {
  const results = new Array(tasks.length);
  let i = 0;
  const workers = Array.from(
    { length: Math.min(concurrency, tasks.length) },
    async () => {
      while (i < tasks.length) {
        const idx = i++;
        results[idx] = await tasks[idx]();
      }
    }
  );
  return Promise.all(workers).then(() => results);
}

async function getProjectMeta(token, ref) {
  // Use the plural /v1/projects/ endpoint which returns extended config
  // (db_ssl, network_restrictions, pool_mode) in addition to name/region.
  const url = `${API}/projects/${ref}`;
  if (_trace) console.error(`[trace] MGMT API: GET ${url}`);
  const r = await fetch(url, {
    headers: { Authorization: `Bearer ${token}`, "User-Agent": UA },
    signal: _timeoutSignal,
  });
  if (_trace) console.error(`[trace] MGMT API STATUS: ${r.status}`);
  if (r.status === 401 || r.status === 403) {
    throw new AuthError(`Project metadata fetch rejected (${r.status})`);
  }
  if (!r.ok) return { name: ref, region: "unknown" };
  return r.json();
}

async function getStorageBuckets(token, ref) {
  try {
    return await sql(token, ref, "SELECT id, name, public, file_size_limit, allowed_mime_types FROM storage.buckets ORDER BY name;");
  } catch {
    return [];
  }
}

// --- Extensions, pg_cron, pg_net, and Vault exposure (spec entry 19) ---

/**
 * Fetch extension list, pg_cron jobs, and vault.decrypted_secrets grants
 * for the extensions-cron classifier. Each sub-query is isolated so that a
 * missing extension (e.g. pg_cron, vault) degrades to empty/null rather
 * than aborting the whole section.
 *
 * @returns {object} { extensions: [], cronJobs: [], vaultGrants: {} | null }
 */
async function getExtensionsCronData(token, ref) {
  // Extensions
  let extensions = [];
  try {
    extensions = await sql(
      token,
      ref,
      "SELECT extname, extversion FROM pg_extension ORDER BY extname;"
    );
  } catch {
    // pg_extension is in pg_catalog — should always exist; swallow defensively
  }

  // pg_cron jobs (only present when the cron extension is installed)
  let cronJobs = [];
  try {
    cronJobs = await sql(
      token,
      ref,
      "SELECT jobid, schedule, command, database, username FROM cron.job ORDER BY jobid;"
    );
  } catch {
    // cron.job doesn't exist → no scheduled jobs
  }

  // vault.decrypted_secrets access grants for anon/authenticated
  let vaultGrants = null;
  try {
    const [row] = await sql(
      token,
      ref,
      `SELECT
         has_table_privilege('anon', 'vault.decrypted_secrets', 'SELECT') AS anon_select,
         has_table_privilege('authenticated', 'vault.decrypted_secrets', 'SELECT') AS auth_select;`
    );
    if (row) {
      vaultGrants = { anon_select: row.anon_select, auth_select: row.auth_select };
    }
  } catch {
    // vault extension not installed → no grants to check
  }

  return { extensions, cronJobs, vaultGrants };
}


async function getAuthConfig(token, ref) {
  try {
    const r = await fetch(`${API}/projects/${ref}/config/auth`, {
      headers: { Authorization: `Bearer ${token}`, "User-Agent": UA },
      signal: _timeoutSignal,
    });
    if (r.status === 401 || r.status === 403) {
      throw new AuthError(`Auth config fetch rejected (${r.status})`);
    }
    if (!r.ok) return null;
    return r.json();
  } catch (e) {
    if (e instanceof AuthError) throw e;
    return null;
  }
}

// Pull project anon API key for active probing.
async function getAnonKey(token, ref) {
  try {
    const r = await fetch(`${API}/projects/${ref}/api-keys?reveal=true`, {
      headers: { Authorization: `Bearer ${token}`, "User-Agent": UA },
      signal: _timeoutSignal,
    });
    if (!r.ok) return null;
    const keys = await r.json();
    const anon = Array.isArray(keys) ? keys.find((k) => k.name === "anon") : null;
    return anon?.api_key || null;
  } catch {
    return null;
  }
}

// List edge functions via Management API, enriching each with CORS config
// (from the details endpoint) and optionally the source body (from the body
// endpoint) for secret-echo / unauthenticated-write analysis.
async function getEdgeFunctions(token, ref) {
  const headers = {
    Authorization: `Bearer ${token}`,
    "User-Agent": UA,
  };
  try {
    const r = await fetch(`${API}/projects/${ref}/functions`, { headers, signal: _timeoutSignal });
    if (!r.ok) return [];
    const list = await r.json();
    if (!Array.isArray(list)) return [];
    // Enrich: fetch details for CORS + body for code analysis (best-effort),
    // parallelized with a bounded pool so a large function count (100+ on big
    // projects) does not serialize.
    const enrichOne = async (f) => {
      const fn = { ...f };
      try {
        const d = await fetch(`${API}/projects/${ref}/functions/${f.id}`, { headers, signal: _timeoutSignal });
        if (d.ok) {
          const detail = await d.json();
          if (detail.cors !== undefined) fn.cors = detail.cors;
        }
      } catch { /* best-effort: CORS stays undefined */ }
      try {
        const b = await fetch(`${API}/projects/${ref}/functions/${f.id}/body`, { headers, signal: _timeoutSignal });
        if (b.ok) fn.body = await b.text();
      } catch { /* best-effort: body stays undefined */ }
      return fn;
    };
    const enriched = await boundedPool(list.map((f) => () => enrichOne(f)), 6);
    return enriched;
  } catch {
    return [];
  }
}

// Active probe: hit PostgREST with the anon key to PROVE the leak.
async function probeAnonAccess(supabaseUrl, anonKey, tableName) {
  const url = `${supabaseUrl}/rest/v1/${encodeURIComponent(tableName)}?limit=1`;
  if (_trace) console.error(`[trace] PROBE: anon GET ${url.replace(anonKey || "", "[ANON_KEY]").slice(0, 200)}`);
  try {
    const r = await fetch(url, {
      headers: {
        apikey: anonKey,
        Authorization: `Bearer ${anonKey}`,
        "User-Agent": UA,
      },
      signal: _timeoutSignal,
    });
    const status = r.status;
    if (_trace) console.error(`[trace] PROBE STATUS: ${status} (${tableName})`);
    if (!r.ok) {
      return { confirmed: false, status, reason: status === 401 ? "anon blocked" : status === 404 ? "table not in PostgREST schema" : `http ${status}` };
    }
    const body = await r.text();
    let row_count = 0;
    let columns = [];
    try {
      const parsed = JSON.parse(body);
      if (Array.isArray(parsed)) {
        row_count = parsed.length;
        if (parsed[0] && typeof parsed[0] === "object") columns = Object.keys(parsed[0]);
      }
    } catch { /* non-JSON */ }
    return {
      confirmed: true,
      status,
      sample: { row_count, columns, bytes_returned: body.length },
    };
  } catch (e) {
    return { confirmed: false, status: 0, reason: `network error: ${e.message}` };
  }
}

// Attempt to sign up a throwaway test user via the Supabase Auth API (/auth/v1/signup).
// When signups are open, creates a REAL user in auth.users (writes to prod DB). Returns
// the user's access_token JWT. When signups are closed or the call fails, returns null.
// The user MUST be deleted after the run via cleanupProbeUser() (see main() finally block).
// WARNING: this is a WRITE operation — only invoked when --probe is explicitly passed.
async function signupTestUser(supabaseUrl, anonKey) {
  const email = `supa360-probe-${Date.now()}@supa360.invalid`;
  const password = "Supa360Probe!2345";
  try {
    const r = await fetch(`${supabaseUrl}/auth/v1/signup`, {
      method: "POST",
      headers: {
        apikey: anonKey,
        Authorization: `Bearer ${anonKey}`,
        "Content-Type": "application/json",
        "User-Agent": UA,
      },
      body: JSON.stringify({ email, password }),
      signal: _timeoutSignal,
    });
    if (!r.ok) return null;
    const data = await r.text();
    try {
      const parsed = JSON.parse(data);
      const jwt = parsed.access_token || null;
      if (jwt) {
        _probeUserJwt = jwt;
        _probeUserRef = await extractUserIdFromJwt(jwt);
      }
      return jwt;
    } catch {
      return null;
    }
  } catch {
    return null;
  }
}

// Extract the user ID (sub claim) from a JWT payload without a library.
function extractUserIdFromJwt(jwt) {
  try {
    const parts = jwt.split(".");
    if (parts.length < 2) return null;
    const payload = Buffer.from(parts[1] + "==", "base64").toString();
    const parsed = JSON.parse(payload);
    return parsed.sub || null;
  } catch {
    return null;
  }
}

// Delete the throwaway probe user after the audit run. Called from main()'s
// finally block to guarantee teardown even when the audit throws.
// No-op if no probe user was created (--probe not passed or signup closed).
export async function cleanupProbeUser(token, ref) {
  if (!_probeUserJwt || !_probeUserRef) return false;
  try {
    const r = await fetch(`${API}/projects/${ref}/auth/users/${_probeUserRef}`, {
      method: "DELETE",
      headers: { Authorization: `Bearer ${token}`, "User-Agent": UA },
      signal: _timeoutSignal,
    });
    // 204 = deleted, 404 = already gone (fine)
    if (r.status === 204 || r.status === 404) {
      _probeUserJwt = null;
      _probeUserRef = null;
      return true;
    }
    return false;
  } catch {
    return false;
  }
}

// Active probe of a table via the authenticated role (user JWT), parallel to
// probeAnonAccess. Same classification: 42501 (blocked) vs 200+[] (safe/empty)
// vs 200+rows (CONFIRMED leak). Returns the same shape as probeAnonAccess.
// (spec entry 6: "Do the same as the 'authenticated' role by minting/using a
// confirmed test user when signup is open")
async function probeAuthenticatedAccess(supabaseUrl, userJwt, tableName) {
  const url = `${supabaseUrl}/rest/v1/${encodeURIComponent(tableName)}?limit=1`;
  if (_trace) console.error(`[trace] AUTH_PROBE: GET ${url.slice(0, 200)}`);
  try {
    const r = await fetch(url, {
      headers: {
        apikey: userJwt,
        Authorization: `Bearer ${userJwt}`,
        "User-Agent": UA,
      },
      signal: _timeoutSignal,
    });
    const status = r.status;
    if (_trace) console.error(`[trace] AUTH_PROBE STATUS: ${status} (${tableName})`);
    if (!r.ok) {
      return { confirmed: false, status, reason: status === 401 ? "auth user blocked" : status === 404 ? "table not in PostgREST schema" : `http ${status}` };
    }
    const body = await r.text();
    let row_count = 0;
    let columns = [];
    try {
      const parsed = JSON.parse(body);
      if (Array.isArray(parsed)) {
        row_count = parsed.length;
        if (parsed[0] && typeof parsed[0] === "object") columns = Object.keys(parsed[0]);
      }
    } catch { /* non-JSON */ }
    return {
      confirmed: row_count > 0,
      status,
      sample: { row_count, columns, bytes_returned: body.length },
    };
  } catch (e) {
    return { confirmed: false, status: 0, reason: `network error: ${e.message}` };
  }
}
// Returns the list/download/upload/delete HTTP statuses + listed count + bytes.
// Best-effort: every call is isolated in try/catch so a routing/method mismatch
// degrades to a 0 status (finding stays 'inferred') instead of aborting the run.
async function probeAnonStorage(supabaseUrl, anonKey, bucketId) {
    const headers = {
    apikey: anonKey,
    Authorization: `Bearer ${anonKey}`,
    "User-Agent": UA,
  };
  const base = `${supabaseUrl}/storage/v1`;
  const enc = encodeURIComponent(bucketId);
  const result = { list: 0, download: null, upload: 0, delete: 0, listed: 0, bytes: 0 };

  // 1. LIST objects (anon SELECT on storage.objects)
  let listedName = null;
  try {
    const r = await fetch(`${base}/object/list/${enc}`, {
      method: "POST",
      headers,
      body: JSON.stringify({ path: "", limit: 5, offset: 0 }),
      signal: _timeoutSignal,
    });
    result.list = r.status;
    if (r.ok) {
      const body = await r.text();
      result.bytes = body.length;
      try {
        const j = JSON.parse(body);
        if (Array.isArray(j)) {
          result.listed = j.length;
          if (j.length && j[0] && j[0].name) listedName = j[0].name;
        }
      } catch { /* non-JSON */ }
    }
  } catch {
    result.list = 0;
  }

  // 2. DOWNLOAD a known object (read confirmation)
  if (listedName) {
    try {
      const r = await fetch(`${base}/object/${enc}/${encodeURIComponent(listedName)}`, { headers });
      result.download = r.status;
    } catch {
      result.download = null;
    }
  }

  // 3. UPLOAD a safe temp key (anon INSERT confirmation). Cleaned up immediately
  //    after so we leave no artifact behind.
  const probeKey = `_360probe_${Date.now()}.txt`;
  try {
    const r = await fetch(`${base}/object/${enc}/${encodeURIComponent(probeKey)}`, {
      method: "POST",
      headers: { ...headers, "Content-Type": "text/plain" },
      body: "360probe",
    });
    result.upload = r.status;
    if (result.upload === 200 || result.upload === 201) {
      try {
        await fetch(`${base}/object/${enc}/${encodeURIComponent(probeKey)}`, { method: "DELETE", headers });
      } catch { /* best-effort cleanup */ }
    }
  } catch {
    result.upload = 0;
  }

  // 4. DELETE a non-existent key (tests anon DELETE authorization; 404 => authorized)
  try {
    const r = await fetch(`${base}/object/${enc}/${encodeURIComponent("_360probe_nonexistent.txt")}`, {
      method: "DELETE",
      headers,
    });
    result.delete = r.status;
  } catch {
    result.delete = 0;
  }

  return result;
}

async function audit(token, ref, opts = {}) {
  const { activeProbe = false, probeVolatile = false, historyEnabled = false, suppressions = [], includeSystemSchemas = false } = opts;
  const findings = [];
  const errors = [];
  const scanFailures = []; // stages that failed to complete (WO-3: no silent clean)

  // Record the PostgreSQL server version for diagnostics (WO-3: permanent diagnostic win).
  let dbVersion = null;
  try {
    const v = await sql(token, ref, "SHOW server_version;");
    dbVersion = (v && v[0] && v[0].server_version) || null;
  } catch { /* version query is best-effort; not a scan failure */ }

  // Shared state across parallel sections (written by Section 1, 2c, 3, 4a;
  // read by Phase 2 sections 2b + 9).
  const state = {
    tables: [],
    funcs: [],
    rpcFunctions: [],
    rpcConfirmed: 0,
    rpcInferred: 0,
    nBucketsScanned: 0,
    nTableColumns: 0,
    nColumnGrants: null,
    nEdgeFunctionsScanned: 0,
    nExtensionsScanned: 0,
    exposedSchemas: [],
    ownersWithLeak: [],
  };

  // Validate token early — if rejected, exit 10 (auth error)
  const meta = await getProjectMeta(token, ref);
  const supabaseUrl = `https://${ref}.supabase.co`;
  const anonKey = activeProbe ? await getAnonKey(token, ref) : null;
  const probeAvailable = !!anonKey;

  // Spec entry 6: when signups are open, mint a throwaway test user to probe
  // tables as the authenticated role (not just anon). This catches leaks that
  // only the authenticated role can reach — the anon probe returns 42501 (blocked)
  // but an authenticated user with a valid JWT can read the data.
  const userJwt = probeAvailable ? await signupTestUser(supabaseUrl, anonKey) : null;
  if (userJwt && _trace) {
    console.error("[trace] Authenticated test user signed up - will use auth probe fallback");
  }

  // --- Shared probe closures (defined once, reused across sections) ---
  const tableProbeFn = probeAvailable
    ? async (tableName) => {
        const pr = await probeAnonAccess(supabaseUrl, anonKey, tableName);
        if (!pr.confirmed && userJwt) {
          const authPr = await probeAuthenticatedAccess(supabaseUrl, userJwt, tableName);
          if (authPr.confirmed) {
            return { status: authPr.status, rowCount: authPr.sample?.row_count ?? 0, bytes: authPr.sample?.bytes_returned ?? 0 };
          }
        }
        return { status: pr.status, rowCount: pr.sample?.row_count ?? 0, bytes: pr.sample?.bytes_returned ?? 0 };
      }
    : null;

  const rpcProbeFn = probeAvailable
    ? async (fnName, payload) => {
        try {
          const r = await fetch(`${supabaseUrl}/rest/v1/rpc/${encodeURIComponent(fnName)}`, {
            method: "POST",
            headers: {
              apikey: anonKey,
              Authorization: `Bearer ${anonKey}`,
              "Content-Type": "application/json",
            },
            body: JSON.stringify(payload),
            signal: _timeoutSignal,
          });
          return { status: r.status, body: r.status === 204 ? "" : await r.text() };
        } catch (e) {
          return { status: 0, body: `network error: ${e.message}` };
        }
      }
    : null;

  const viewProbeFn = probeAvailable
    ? async (viewName) => {
        const pr = await probeAnonAccess(supabaseUrl, anonKey, viewName);
        return { status: pr.status, rowCount: pr.sample?.row_count ?? 0, bytes: pr.sample?.bytes_returned ?? 0 };
      }
    : null;

  const realtimeProbeFn = probeAvailable
    ? async (tableName) => {
        const pr = await probeAnonAccess(supabaseUrl, anonKey, tableName);
        return { status: pr.status, rowCount: pr.sample?.row_count ?? 0, bytes: pr.sample?.bytes_returned ?? 0 };
      }
    : null;

  const storageProbeFn = probeAvailable
    ? async (bucketId) => {
        const pr = await probeAnonStorage(supabaseUrl, anonKey, bucketId);
        return {
          list: pr.list,
          download: pr.download,
          upload: pr.upload,
          delete: pr.delete,
          listed: pr.listed,
          bytes: pr.bytes,
        };
      }
    : null;

  // === PHASE 0: Resolve scan schemas (WO-14) ===
  // PostgREST db_schema is the authoritative exposure list (NOT the
  // management connection's search_path — see audit.js:1387-1391 for the
  // original comment). scanSchemas = exposedSchemas ∪ schemas containing user
  // relations, minus Supabase platform schemas (opt-in via --include-system-schemas).
  // All enumeration queries below inline this set as n.nspname = ANY(<schemaArrayStr>).
  state.exposedSchemas = [];
  state.dataApiEnabled = false;
  try {
    const pr = await fetch(`${API}/projects/${ref}/postgrest`, {
      headers: { Authorization: `Bearer ${token}`, "User-Agent": UA },
      signal: _timeoutSignal,
    });
    if (pr.ok) {
      const pgCfg = await pr.json();
      // db_schema is a comma-separated list of schema names, or "" for off.
      const dbSchema = pgCfg.db_schema || "";
      state.dataApiEnabled = dbSchema !== "";
      state.exposedSchemas = String(dbSchema)
        .split(",")
        .map((s) => s.trim().replace(/^"|"$/g, ""))
        .filter((s) => s && !s.startsWith("$")); // filter $user and $-prefixed tokens
    } else {
      // WO-14: NEVER degrade to an empty list silently — push to errors
      // so scan_complete === false and the report shows INCOMPLETE.
      errors.push({
        check: "postgrest_config",
        error: `PostgREST config endpoint returned HTTP ${pr.status}: ${pr.statusText || ""}`,
      });
    }
  } catch (e) {
    if (e instanceof AuthError) throw e;
    errors.push({
      check: "postgrest_config",
      error: `PostgREST config fetch failed: ${e.message || String(e)}`,
    });
  }

  // Query all non-system schemas that contain user relations (tables/views).
  // This catches schemas with user data not listed in db_schema (e.g. realtime,
  // storage — accessed by the audit but not always in the exposed list).
  try {
    const relSchemas = await sql(
      token, ref,
      `SELECT DISTINCT n.nspname
         FROM pg_class c
         JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname NOT LIKE 'pg\\_%'
          AND n.nspname != 'information_schema'
          AND c.relkind IN ('r', 'p', 'v', 'm')
       ORDER BY n.nspname;`
    );
    const userRelationSchemas = (relSchemas || []).map((r) => r.nspname);
    // Union: exposedSchemas ∪ userRelationSchemas (deduplicated)
    state.scanSchemas = [...new Set([...state.exposedSchemas, ...userRelationSchemas])];

    // WO-14 (BUG 2): exclude Supabase platform schemas by default. These are
    // vendor-controlled (storage internals, realtime internals, auth, vault,
    // etc.) and produce noise/false-positives when audited as user data.
    // Dedicated checks (processStorage, processRealtime) query their own
    // tables directly, so excluding the schema here does NOT lose any
    // user-actionable finding. Opt-in via --include-system-schemas.
    if (!includeSystemSchemas) {
      const PLATFORM_SCHEMA_PATTERNS = [
        /^pg_/, /^pgsodium/, /_realtime$/, /^_analytics/,
      ];
      const PLATFORM_SCHEMA_SET = new Set([
        "storage", "realtime", "auth", "vault", "graphql", "graphql_public",
        "extensions", "cron", "net", "pgbouncer",
      ]);
      state.scanSchemas = state.scanSchemas.filter((s) => {
        if (PLATFORM_SCHEMA_SET.has(s)) return false;
        if (s.startsWith("supabase_")) return false;
        if (PLATFORM_SCHEMA_PATTERNS.some((p) => p.test(s))) return false;
        return true;
      });
    }
  } catch (e) {
    if (e instanceof AuthError) throw e;
    // Fall back to just the exposed schemas — the config fetch error was
    // already recorded above.
    state.scanSchemas = [...state.exposedSchemas];
  }

  // Build a SQL array literal for inlining into queries:
  //   n.nspname = ANY(ARRAY['public','api'])
  // Schema names come from pg_namespace / PostgREST config — escape single
  // quotes for SQL safety.
  state.schemaArrayStr = state.scanSchemas.length > 0
    ? "ARRAY[" + state.scanSchemas.map((s) => `'${String(s).replace(/'/g, "''")}'`).join(",") + "]"
    : "ARRAY[]::text[]";

  // === PHASE 1: Independent check sections (parallel, bounded pool of 6) ===
  // Each section is a closure that updates shared `state` + pushes to
  // `findings`/`errors`. AuthError is re-thrown (aborts whole audit);
  // all other errors are caught + recorded.
  // Bug 4 fix: heavy SQL queries use sqlBatched() (id-batch, no OFFSET) and
  // independent sections run concurrently so a slow one does not block the rest.

  const phase1Tasks = [
    // 1. Tables: RLS + policies + grants + PII columns (sqlBatched — was the SQL 544 crash)
    async () => {
      try {
        // 1. Tables: RLS status + full policy quals (json_agg via correlated subquery)
        //    + anon/auth grants + column names for PII classification.
        //    Audits EVERY schema in scanSchemas (resolved in Phase 0 from
        //    PostgREST db_schema ∪ user-relation schemas), not just public
        //    — spec entry 13. classifyTable()/processTables() live in
        //    scripts/checks/rls.js (pure, unit-tested).
        // Bug 4 fix: sqlBatched() splits this into a cheap oid-list query +
        // detail query (with correlated json_agg subqueries) fetched in
        // batches of 25 oids via WHERE c.oid = ANY(ARRAY[...]). Each heavy
        // query touches exactly 25 tables — no OFFSET re-scan.
        state.tables = await sqlBatched(
          token,
          ref,
          `SELECT c.oid, n.nspname AS schema_name, c.relname AS table_name
           FROM pg_class c
           JOIN pg_namespace n ON n.oid = c.relnamespace
           WHERE n.nspname = ANY(${state.schemaArrayStr}) AND c.relkind IN ('r', 'p')
           ORDER BY c.oid;`,
`SELECT
         n.nspname AS schema_name,
         c.relname AS table_name,
         c.relrowsecurity AS rls_enabled,
         COALESCE((SELECT json_agg(json_build_object('policyname',p.policyname,'cmd',p.cmd,'roles',p.roles,'qual',p.qual,'with_check',p.with_check)) FROM pg_policies p WHERE p.schemaname = n.nspname AND p.tablename = c.relname),'[]'::json) AS policies,
         has_table_privilege('anon', quote_ident(n.nspname)||'.'||quote_ident(c.relname), 'SELECT') AS anon_select,
         has_table_privilege('anon', quote_ident(n.nspname)||'.'||quote_ident(c.relname), 'INSERT') AS anon_insert,
         has_table_privilege('anon', quote_ident(n.nspname)||'.'||quote_ident(c.relname), 'UPDATE') AS anon_update,
         has_table_privilege('anon', quote_ident(n.nspname)||'.'||quote_ident(c.relname), 'DELETE') AS anon_delete,
         has_table_privilege('authenticated', quote_ident(n.nspname)||'.'||quote_ident(c.relname), 'SELECT') AS auth_select,
         has_table_privilege('authenticated', quote_ident(n.nspname)||'.'||quote_ident(c.relname), 'INSERT') AS auth_insert,
         has_table_privilege('authenticated', quote_ident(n.nspname)||'.'||quote_ident(c.relname), 'UPDATE') AS auth_update,
         has_table_privilege('authenticated', quote_ident(n.nspname)||'.'||quote_ident(c.relname), 'DELETE') AS auth_delete,
         COALESCE((SELECT json_agg(json_build_object('name', a.attname, 'data_type', a.atttypid::regtype)) FROM pg_attribute a WHERE a.attrelid = c.oid AND a.attnum > 0 AND a.attisdropped = false), '[]'::json) AS columns
       FROM pg_class c
       JOIN pg_namespace n ON n.oid = c.relnamespace
       WHERE n.nspname = ANY(${state.schemaArrayStr}) AND c.relkind IN ('r', 'p')
         AND c.oid = ANY(__OID_BATCH__)
       ORDER BY n.nspname, c.relname;`
        );

        // Classify sensitive columns per table via the shared PII classifier (entry 15).
        // classifyTable escalates to critical when a confirmed leak touches a
        // sensitive column.
        const tablesWithPII = state.tables.map((t) => ({
          ...t,
          sensitive_columns: scanForSensitiveColumns(t.columns || []),
        }));
        state.nTableColumns = tablesWithPII.reduce((acc, t) => acc + (t.columns?.length || 0), 0);

        const classified = await processTables(tablesWithPII, tableProbeFn);
        for (const f of classified) {
          findings.push(normalizeFinding({ ...CHECKS[f.check], ...f }));
        }

        // Entry 37: fetch ALL btree-indexed columns per table (cheap catalog
        // metadata query — no correlated subqueries, safe to run as-is sql()
        // not batch). Uses ANY(indkey) — not just indkey[1] — so PK + unique
        // index columns are all covered (architect: PK/unique count as covering).
        let btreeIndex = new Map();
        try {
          const idxRows = await sql(
            token,
            ref,
            `SELECT DISTINCT
                 c.relname AS table_name,
                 a.attname AS column_name
               FROM pg_index i
               JOIN pg_class c ON c.oid = i.indrelid
               JOIN pg_namespace n ON n.oid = c.relnamespace
               JOIN pg_attribute a ON a.attrelid = c.oid AND a.attnum = ANY(i.indkey)
               JOIN pg_class ic ON ic.oid = i.indexrelid
               JOIN pg_am am ON am.oid = ic.relam
               WHERE n.nspname = ANY(${state.schemaArrayStr})
                 AND c.relkind IN ('r', 'p')
                 AND am.amname = 'btree'
               ORDER BY c.relname, a.attname;`
          );
          for (const row of idxRows) {
            if (!btreeIndex.has(row.table_name)) btreeIndex.set(row.table_name, []);
            btreeIndex.get(row.table_name).push(row.column_name);
          }
        } catch { /* catalog query may fail on some pg versions — degrade gracefully */ }

        // Entries 36-39: RLS performance checks on policy expressions.
        // processRlsPerf is pure — classifyPolicyPerf (36), classifyUnindexedPolicy (37),
        // classifyJoinInPolicy (38), classifyPublicRolePolicy (39), all unit-tested.
        const perfFindings = processRlsPerf(tablesWithPII, btreeIndex);
        for (const f of perfFindings) {
          findings.push(normalizeFinding({ ...CHECKS[f.check], ...f }));
        }
      } catch (e) {
        if (e instanceof AuthError) throw e;
        errors.push({ check: "rls_tables", error: e.message });
      }
    },

    // 2. SECURITY DEFINER functions: executable-by-anon AND missing search_path
    async () => {
      try {
        state.funcs = await sqlBatched(
          token,
          ref,
          `SELECT p.oid FROM pg_proc p
           JOIN pg_namespace n ON n.oid = p.pronamespace
           WHERE n.nspname = ANY(${state.schemaArrayStr}) AND p.prosecdef = true
           ORDER BY p.oid;`,
          `SELECT
             p.proname AS function_name,
             n.nspname AS schema_name,
             p.prosecdef AS security_definer,
             pg_get_function_result(p.oid) AS return_type,
             has_function_privilege('anon', p.oid, 'EXECUTE') AS anon_execute,
             p.proconfig AS config
           FROM pg_proc p
           JOIN pg_namespace n ON n.oid = p.pronamespace
           WHERE n.nspname = ANY(${state.schemaArrayStr}) AND p.prosecdef = true
             AND p.oid = ANY(__OID_BATCH__);`
        );

        for (const f of state.funcs) {
          if (f.return_type === "trigger") continue;
          if (f.anon_execute) {
            findings.push(normalizeFinding({
              ...CHECKS.function_security_definer_anon_executable,
              check: "function_security_definer_anon_executable",
              target: f.function_name,
              confidence: "inferred",
              evidence: { returns: f.return_type, prosecdef: f.security_definer },
              fix: {
                sql: [`REVOKE EXECUTE ON FUNCTION ${f.schema_name || "public"}.${f.function_name} FROM anon;`],
                rollback_sql: [],
                requires_service_role: false,
              },
            }));
          }
          const hasSearchPath = Array.isArray(f.config) && f.config.some((c) => typeof c === "string" && c.toLowerCase().startsWith("search_path="));
          if (!hasSearchPath) {
            findings.push(normalizeFinding({
              ...CHECKS.function_no_search_path,
              check: "function_no_search_path",
              target: f.function_name,
              confidence: "inferred",
              evidence: { returns: f.return_type, current_config: f.config },
              fix: {
                sql: [`ALTER FUNCTION ${f.schema_name || "public"}.${f.function_name} SET search_path = ${f.schema_name || "public"}, pg_temp;`],
                rollback_sql: [],
                requires_service_role: false,
              },
            }));
          }
        }
      } catch (e) {
        if (e instanceof AuthError) throw e;
        errors.push({ check: "function_secdef", error: e.message });
      }
    },

    // 2c. ALL anon/authenticated-EXECUTE functions (secdef AND invoker) + active probe
    async () => {
      try {
        const rpcFuncs = await sqlBatched(
          token,
          ref,
          `SELECT p.oid FROM pg_proc p
           JOIN pg_namespace n ON n.oid = p.pronamespace
           WHERE n.nspname = ANY(${state.schemaArrayStr})
             AND (has_function_privilege('anon', p.oid, 'EXECUTE') OR has_function_privilege('authenticated', p.oid, 'EXECUTE'))
             AND pg_get_function_result(p.oid) <> 'trigger'
           ORDER BY p.oid;`,
          `SELECT
             p.proname AS function_name,
             n.nspname AS schema_name,
             p.prosecdef AS security_definer,
             p.provolatile AS volatility,
             pg_get_function_result(p.oid) AS return_type,
             has_function_privilege('anon', p.oid, 'EXECUTE') AS anon_execute,
             has_function_privilege('authenticated', p.oid, 'EXECUTE') AS auth_execute,
             p.proconfig AS config,
             pg_get_function_arguments(p.oid) AS arg_signature
           FROM pg_proc p
           JOIN pg_namespace n ON n.oid = p.pronamespace
           WHERE n.nspname = ANY(${state.schemaArrayStr})
             AND (has_function_privilege('anon', p.oid, 'EXECUTE') OR has_function_privilege('authenticated', p.oid, 'EXECUTE'))
             AND pg_get_function_result(p.oid) <> 'trigger'
             AND p.oid = ANY(__OID_BATCH__)
           ORDER BY p.proname;`
        );

        state.rpcFunctions = rpcFuncs.map((f) => ({
          function_name: f.function_name,
          schema_name: f.schema_name,
          prosecdef: f.security_definer,
          provolatile: f.volatility,
          return_type: f.return_type,
          anon_execute: f.anon_execute,
          auth_execute: f.auth_execute,
          config: f.config,
          args: parseArgSignature(f.arg_signature),
        }));

        const { findings: rpcFindings, confirmed_count, inferred_count } = await probeRpcs(state.rpcFunctions, rpcProbeFn, probeVolatile);
        state.rpcConfirmed = confirmed_count;
        state.rpcInferred = inferred_count;
        for (const f of rpcFindings) {
          findings.push(normalizeFinding({ ...CHECKS[f.check], ...f }));
        }
      } catch (e) {
        if (e instanceof AuthError) throw e;
        errors.push({ check: "rpc_probe", error: e.message });
      }
    },

    // 2d. SECURITY DEFINER function body analysis
    async () => {
      try {
        const bodyFuncs = await sqlBatched(
          token,
          ref,
          `SELECT p.oid FROM pg_proc p
           JOIN pg_namespace n ON n.oid = p.pronamespace
           WHERE n.nspname = ANY(${state.schemaArrayStr})
             AND p.prosecdef = true
             AND (has_function_privilege('anon', p.oid, 'EXECUTE') OR has_function_privilege('authenticated', p.oid, 'EXECUTE'))
             AND pg_get_function_result(p.oid) <> 'trigger'
           ORDER BY p.oid;`,
          `SELECT
             p.proname AS function_name,
             n.nspname AS schema_name,
             p.prosecdef AS security_definer,
             pg_get_function_result(p.oid) AS return_type,
             has_function_privilege('anon', p.oid, 'EXECUTE') AS anon_execute,
             has_function_privilege('authenticated', p.oid, 'EXECUTE') AS auth_execute,
             p.proconfig AS config,
             pg_get_functiondef(p.oid) AS body
           FROM pg_proc p
           JOIN pg_namespace n ON n.oid = p.pronamespace
           WHERE n.nspname = ANY(${state.schemaArrayStr})
             AND p.prosecdef = true
             AND (has_function_privilege('anon', p.oid, 'EXECUTE') OR has_function_privilege('authenticated', p.oid, 'EXECUTE'))
             AND pg_get_function_result(p.oid) <> 'trigger'
             AND p.oid = ANY(__OID_BATCH__)
           ORDER BY p.proname;`
        );

        const bodyObjs = bodyFuncs.map((f) => ({
          function_name: f.function_name,
          schema_name: f.schema_name,
          prosecdef: f.security_definer,
          return_type: f.return_type,
          anon_execute: f.anon_execute,
          auth_execute: f.auth_execute,
          config: f.config,
          body: f.body,
        }));

        const bodyFindings = analyzeFunctionBodies(bodyObjs);
        for (const f of bodyFindings) {
          findings.push(normalizeFinding({ ...CHECKS[f.check], ...f }));
        }
      } catch (e) {
        if (e instanceof AuthError) throw e;
        errors.push({ check: "function_body", error: e.message });
      }
    },

    // 2e. Views & materialized views with anon/auth SELECT grants
    async () => {
      try {
        const viewRows = await sqlBatched(
          token,
          ref,
          `SELECT c.oid FROM pg_class c
           JOIN pg_namespace n ON n.oid = c.relnamespace
           WHERE n.nspname = ANY(${state.schemaArrayStr}) AND c.relkind IN ('v', 'm')
           ORDER BY c.oid;`,
          `SELECT
             n.nspname AS schema_name,
             c.relname AS view_name,
             c.relkind = 'm' AS matview,
             COALESCE(c.reloptions::text[] @> ARRAY['security_invoker=true'] OR c.reloptions::text[] @> ARRAY['security_invoker=on'], false) AS security_invoker,
             has_table_privilege('anon', n.nspname || '.' || quote_ident(c.relname), 'SELECT') AS anon_select,
             has_table_privilege('authenticated', n.nspname || '.' || quote_ident(c.relname), 'SELECT') AS auth_select,
             COALESCE((
               SELECT json_agg(a.attname)
               FROM pg_attribute a
               WHERE a.attrelid = c.oid AND a.attnum > 0 AND NOT a.attisdropped
             ), '[]'::json) AS columns
           FROM pg_class c
           JOIN pg_namespace n ON n.oid = c.relnamespace
           WHERE n.nspname = ANY(${state.schemaArrayStr}) AND c.relkind IN ('v', 'm')
             AND c.oid = ANY(__OID_BATCH__)
           ORDER BY n.nspname, c.relname;`
        );

        const viewFindings = await processViews(viewRows, viewProbeFn);
        for (const f of viewFindings) {
          findings.push(normalizeFinding({ ...CHECKS[f.check], ...f }));
        }
      } catch (e) {
        if (e instanceof AuthError) throw e;
        errors.push({ check: "views", error: e.message });
      }
    },

    // 3. Default privileges (spec entry 22)
    async () => {
      try {
        const defaults = await sql(
          token,
          ref,
          `SELECT defaclrole::regrole::text AS owner_role,
                  d.defaclobjtype AS defaclobjtype,
                  d.defaclacl::text AS acl,
                  n.nspname AS schema_name
           FROM pg_default_acl d
           JOIN pg_namespace n ON n.oid = d.defaclnamespace
           WHERE n.nspname = ANY(${state.schemaArrayStr})
             AND defaclrole::regrole::text = ANY (ARRAY['postgres','supabase_admin'])
             AND d.defaclobjtype = ANY (ARRAY['r','S','f']);`
        );

        // WO-10 gap: determine which roles actually create objects in the scanned
        // schemas. A pg_default_acl row fires only when defaclrole creates objects.
        // If supabase_admin owns zero objects, its default ACL row is inert —
        // downgrade to INFO, don't treat as an active leak.
        const creatingRoles = new Set();
        try {
          const owners = await sql(
            token,
            ref,
            `SELECT DISTINCT pg_get_userbyid(c.relowner) AS creating_role
               FROM pg_class c
               JOIN pg_namespace n ON n.oid = c.relnamespace
               WHERE n.nspname = ANY(${state.schemaArrayStr})
                 AND c.relkind IN ('r', 'p')`
          );
          for (const row of (owners || [])) {
            if (row.creating_role) creatingRoles.add(row.creating_role);
          }
          // The audit connection's current_user can also create objects.
          const cu = await sql(token, ref, `SELECT current_user;`);
          if (cu && cu[0] && cu[0].current_user) creatingRoles.add(cu[0].current_user);
        } catch { /* best-effort — creating role resolution is advisory */ }

        const creatingRolesArr = [...creatingRoles];
        const privFindings = classifyDefaultAcls(defaults, creatingRolesArr);
        // ownersWithLeak drives data_api_auto_expose_on — only include GOVERNING
        // owners (medium+ severity), not inert platform-default rows (info).
        state.ownersWithLeak = [...new Set(
          privFindings
            .filter((f) => f.severity === "medium" || f.severity === "high" || f.severity === "critical")
            .map((f) => f.evidence.owner_role)
        )];
        for (const f of privFindings) {
          findings.push(normalizeFinding({ ...CHECKS.default_privileges_not_revoked, ...f }));
        }
      } catch (e) {
        if (e instanceof AuthError) throw e;
        errors.push({ check: "default_privileges", error: e.message });
      }
    },

    // 4a. Column-level grants + non-public exposed schemas (spec entry 13)
    async () => {
      try {
        // PostgREST db_schema was resolved in Phase 0 (audit.js:WO-14) —
        // the management connection's search_path is NOT used (it may contain
        // $user placeholder or schemas PostgREST does not expose).
        // The fetch + error handling lives in Phase 0; here we just consume
        // state.exposedSchemas and state.dataApiEnabled.

        // Data API disabled: db_schema="" means REST is off — secure state (INFO).
        if (!state.dataApiEnabled) {
          findings.push(normalizeFinding({
            check: "data_api_disabled",
            category: "coverage-data-api",
            severity: "info",
            confidence: "inferred",
            target: "project:rest",
            evidence: { db_schema: "", data_api_enabled: false },
            fix: { sql: [], rollback_sql: [], dashboard_action: null, management_api_action: null, requires_service_role: false },
            references: ["https://supabase.com/docs/guides/api"],
          }));
        }

        const schemaFindings = findExposedSchemas(state.exposedSchemas);
        for (const f of schemaFindings) {
          findings.push(normalizeFinding({ ...CHECKS[f.check], ...f }));
        }

        // Enumerate column-level anon/authenticated SELECT grants across ALL
        // schemas in scanSchemas (resolved in Phase 0 from db_schema ∪ user-relation schemas).
        const colRows = await sqlBatched(
          token,
          ref,
          `SELECT DISTINCT c.oid FROM pg_attribute a
           JOIN pg_class c ON c.oid = a.attrelid
           JOIN pg_namespace n ON n.oid = c.relnamespace
           WHERE a.attnum > 0 AND NOT a.attisdropped
             AND c.relkind IN ('r', 'p', 'v', 'm')
             AND n.nspname = ANY(${state.schemaArrayStr})
           ORDER BY c.oid;`,
          `SELECT
             n.nspname AS schema_name,
             c.relname AS table_name,
             a.attname AS column_name,
             a.atttypid::regtype AS data_type,
             has_column_privilege('anon', quote_ident(n.nspname)||'.'||quote_ident(c.relname), a.attname, 'SELECT') AS anon_col_select,
             has_column_privilege('authenticated', quote_ident(n.nspname)||'.'||quote_ident(c.relname), a.attname, 'SELECT') AS auth_col_select,
             has_table_privilege('anon', quote_ident(n.nspname)||'.'||quote_ident(c.relname), 'SELECT') AS anon_table_select,
             has_table_privilege('authenticated', quote_ident(n.nspname)||'.'||quote_ident(c.relname), 'SELECT') AS auth_table_select
           FROM pg_attribute a
           JOIN pg_class c ON c.oid = a.attrelid
           JOIN pg_namespace n ON n.oid = c.relnamespace
           WHERE a.attnum > 0 AND NOT a.attisdropped
             AND c.relkind IN ('r', 'p', 'v', 'm')
             AND n.nspname = ANY(${state.schemaArrayStr})
             AND c.oid = ANY(__OID_BATCH__)
             AND (has_column_privilege('anon', quote_ident(n.nspname)||'.'||quote_ident(c.relname), a.attname, 'SELECT')
                  OR has_column_privilege('authenticated', quote_ident(n.nspname)||'.'||quote_ident(c.relname), a.attname, 'SELECT'))
           ORDER BY n.nspname, c.relname, a.attnum;`
        );

        state.nColumnGrants = colRows.length;
        const colFindings = processColumnGrants(colRows);
        for (const f of colFindings) {
          findings.push(normalizeFinding({ ...CHECKS[f.check], ...f }));
        }
      } catch (e) {
        if (e instanceof AuthError) throw e;
        errors.push({ check: "schema_grants", error: e.message });
      }
    },

    // 4. Storage: storage.objects POLICIES per bucket (entry 11) + public flag (entry 12)
    async () => {
      try {
        const buckets = await getStorageBuckets(token, ref);
        // policies on storage.objects (anon INSERT/UPDATE/DELETE/SELECT leaks are policy-level)
        const policies =
          (await sql(
            token,
            ref,
            "SELECT policyname, cmd, roles, qual, with_check FROM pg_policies WHERE schemaname = 'storage' AND tablename = 'objects' ORDER BY policyname;"
          )) || [];

        state.nBucketsScanned = buckets.length;

        const storageFindings = await processStorage(buckets, policies, storageProbeFn);
        for (const f of storageFindings) {
          findings.push(normalizeFinding({ ...CHECKS[f.check], ...f }));
        }

        // Bucket-level public flag (entry 11 shorthand; config hygiene is entry 12).
        for (const b of buckets) {
          if (b.public) {
            findings.push(normalizeFinding({
              ...CHECKS.storage_bucket_public,
              check: "storage_bucket_public",
              target: `bucket:${b.name}`,
              confidence: "inferred",
              evidence: { id: b.id, file_size_limit: b.file_size_limit, allowed_mime_types: b.allowed_mime_types },
              fix: {
                sql: [`UPDATE storage.buckets SET public = false WHERE id = '${b.id}'; -- only if you don't need public CDN-style access`],
                rollback_sql: [],
                requires_service_role: false,
              },
            }));
          }
        }

        // Entry 12: bucket config hygiene (missing file_size_limit / allowed_mime_types).
        const configFindings = findBucketConfigIssues(buckets);
        for (const f of configFindings) {
          findings.push(normalizeFinding({ ...CHECKS[f.check], ...f }));
        }
      } catch (e) {
        if (e instanceof AuthError) throw e;
        errors.push({ check: "storage_policies", error: e.message });
      }
    },

    // 5. Auth config (pure analysis extracted to scripts/checks/auth.js)
    async () => {
      try {
        const authCfg = await getAuthConfig(token, ref);
        if (authCfg) {
          const authFindings = analyzeAuthConfig(authCfg, ref);
          for (const f of authFindings) {
            findings.push(normalizeFinding({ ...CHECKS[f.check], ...f }));
          }
        }
      } catch (e) {
        if (e instanceof AuthError) throw e;
        errors.push({ check: "auth_config", error: e.message });
      }
    },

    // 6. Edge Functions security (spec entry 17)
    async () => {
      try {
        const edgeFunctions = await getEdgeFunctions(token, ref);
        state.nEdgeFunctionsScanned = edgeFunctions.length;
        const edgeFindings = processEdgeFunctions(edgeFunctions, ref);
        for (const f of edgeFindings) {
          findings.push(normalizeFinding({ ...CHECKS[f.check], ...f }));
        }
      } catch (e) {
        if (e instanceof AuthError) throw e;
        errors.push({ check: "edge_functions", error: e.message });
      }
    },

    // 7. Network & database exposure (spec entry 18)
    //    Uses the project metadata already fetched via getProjectMeta
    async () => {
      try {
        const netFindings = processNetworkDb(meta, ref);
        for (const f of netFindings) {
          findings.push(normalizeFinding({ ...CHECKS[f.check], ...f }));
        }
      } catch (e) {
        if (e instanceof AuthError) throw e;
        errors.push({ check: "network_db", error: e.message });
      }
    },

    // 8. Extensions, pg_cron, pg_net, and Vault exposure (spec entry 19)
    async () => {
      try {
        const extData = await getExtensionsCronData(token, ref);
        state.nExtensionsScanned = (extData.extensions || []).length;
        const extCronFindings = processExtensionsCron(extData, ref);
        for (const f of extCronFindings) {
          findings.push(normalizeFinding({ ...CHECKS[f.check], ...f }));
        }
      } catch (e) {
        if (e instanceof AuthError) throw e;
        errors.push({ check: "extensions_cron", error: e.message });
      }
    },

    // WO-9: Historical exposure — pg_stat_statements for anon/authenticated queries.
    // Opt-in via --history. Reports actual historical data access (not just
    // potential exposure). Degrades gracefully if the extension is absent.
    async () => {
      if (!historyEnabled) return;
      try {
        // sql() auto-tags all queries with /* supa360-probe */ so they're
        // excluded from historical analysis — this is our audit query, not attacker activity.
        const histRows = await sql(
          token,
          ref,
          `SELECT r.rolname, s.query, s.calls, s.rows, s.stats_since
             FROM extensions.pg_stat_statements s
             JOIN pg_roles r ON r.oid = s.userid
             WHERE r.rolname IN ('anon', 'authenticated')
             ORDER BY s.rows DESC, s.calls DESC;`
        );
        // Build tableNames from the audited relation list (what we scanned).
        const tableNames = state.tables ? state.tables.map((t) => t.table_name) : [];

        // Build tableSchemas from ALL relations (not just Data-API schemas).
        // "what did we audit" (tableNames) vs "what relation does this statement
        // name" (tableSchemas) are different questions. storage.objects may not
        // be in the Data-API schema list but still appears in pg_stat_statements.
        const tableSchemas = {};
        try {
          const allRelations = await sql(
            token,
            ref,
            `SELECT n.nspname AS schema_name, c.relname AS table_name
               FROM pg_class c
               JOIN pg_namespace n ON n.oid = c.relnamespace
               WHERE c.relkind IN ('r', 'p')
                 AND n.nspname NOT IN ('pg_catalog', 'information_schema', 'pg_toast')`
          );
          for (const t of (allRelations || [])) {
            // First schema wins (search_path order). Don't overwrite.
            if (!tableSchemas[t.table_name]) {
              tableSchemas[t.table_name] = t.schema_name;
            }
          }
        } catch { /* best-effort — schema resolution degrades to bare names */ }
        const { findings: histFindings, history_available, stats_since, note, excluded_count } = processHistoricalAccess(histRows, tableNames, tableSchemas);
        // Record history availability even if no findings (WO-9: never "clean" on absence)
        state.history = { history_available, stats_since, note, excluded_count };
        for (const f of histFindings) {
          findings.push(normalizeFinding({ ...f, evidence: { ...f.evidence, history_available, stats_since } }));
        }
      } catch (e) {
        if (e instanceof AuthError) throw e;
        // pg_stat_statements may not be installed — record as history unavailable
        state.history = { history_available: false, stats_since: null, note: `pg_stat_statements query failed: ${e.message}` };
        errors.push({ check: "history", error: "pg_stat_statements query failed: " + e.message.slice(0, 200) });
      }
    },
  ];

  // Run Phase 1 sections concurrently (bounded pool of 6). AuthError from any
  // section propagates and aborts the entire audit.
  await boundedPool(phase1Tasks, 6);

  // === PHASE 2: Dependent check sections (realtime + data_api) ===
  // These depend on shared state from Phase 1:
  //   realtime needs `tables` (for RLS map)
  //   data_api needs `tables`, `rpcFunctions`, `ownersWithLeak`, `exposedSchemas`

  const phase2Tasks = [
    // 2b. Realtime publication WITHOUT RLS + realtime.messages broadcast/presence
    //     (spec entry 20 — pure module: scripts/checks/realtime.js)
    async () => {
      let realtimeData = { realtimeTables: [], realtimeMessages: null };
      try {
        const realtimeTables = await sql(
          token,
          ref,
          `SELECT schemaname, tablename FROM pg_publication_tables WHERE pubname = 'supabase_realtime' AND schemaname = ANY(${state.schemaArrayStr});`
        );
        const tableRlsMap = new Map(state.tables.map((t) => [t.table_name, t.rls_enabled]));
        realtimeData.realtimeTables = realtimeTables.map((t) => ({
          table_name: t.tablename,
          schema_name: t.schemaname,
          rls_enabled: tableRlsMap.get(t.tablename),
          in_publication: true,
        }));
      } catch { /* publication may not exist */ }

      // realtime.messages (broadcast/presence) config
      try {
        const msgs = await sql(
          token,
          ref,
          `SELECT
             COALESCE(c.relrowsecurity, false) AS rls_enabled,
             has_table_privilege('anon', 'realtime.messages', 'SELECT') AS anon_select,
             has_table_privilege('authenticated', 'realtime.messages', 'SELECT') AS auth_select,
             has_table_privilege('anon', 'realtime.messages', 'INSERT') AS anon_insert,
             has_table_privilege('authenticated', 'realtime.messages', 'INSERT') AS auth_insert,
             has_table_privilege('anon', 'realtime.messages', 'DELETE') AS anon_delete,
             EXISTS(
               SELECT 1 FROM pg_policies WHERE schemaname = 'realtime' AND tablename = 'messages'
             ) AS has_policies
           FROM pg_class c
           JOIN pg_namespace n ON n.oid = c.relnamespace
           WHERE n.nspname = 'realtime' AND c.relname = 'messages';`
        );
        if (msgs && msgs.length > 0) {
          realtimeData.realtimeMessages = msgs[0];
        }
      } catch { /* realtime.messages may not exist */ }

      const realtimeFindings = await processRealtime(realtimeData, ref, realtimeProbeFn);
      for (const f of realtimeFindings) {
        findings.push(normalizeFinding({ ...CHECKS[f.check], ...f }));
      }
    },

    // 9. Data API surface configuration (spec entry 21)
    //    Reports "Automatically expose new tables" toggle state, exposed schemas/
    //    tables/functions counts, and the supabase_admin default-privileges limitation.
    //    Reuses ownersWithLeak (section 3) + exposedSchemas (section 4a) + tables/rpcFunctions counts.
    async () => {
      try {
        const dataApiConfig = {
          auto_expose: state.ownersWithLeak.length > 0,
          data_api_enabled: state.dataApiEnabled,
          leaky_owner_roles: state.ownersWithLeak,
          exposed_schemas: state.exposedSchemas,
          table_count: state.tables.length,
          function_count: state.rpcFunctions.length,
        };
        const dataApiFindings = processDataApi(dataApiConfig, ref);
        for (const f of dataApiFindings) {
          findings.push(normalizeFinding({ ...CHECKS[f.check], ...f }));
        }
      } catch (e) {
        if (e instanceof AuthError) throw e;
        errors.push({ check: "data_api", error: e.message });
      }
    },
  ];

  await boundedPool(phase2Tasks, 2);

  // Apply suppression allowlist from .supa360.json (entry 29).
  // Suppressed findings still appear in output (auditable) but are excluded
  // from fail-gate counts via computeExitCode skipping suppressed:true.
  let staleSuppressions = [];
  if (suppressions && suppressions.length > 0) {
    findings = applySuppressions(findings, suppressions);
    staleSuppressions = checkStaleSuppressions(findings, suppressions);
  }

  // Normalize + sort all findings (already normalized per-push, sort suffices)
  const normalized = sortFindings(findings);

  // Count active probes
  const probed = normalized.filter((f) => f.probe).length;
  const confirmed = normalized.filter((f) => f.probe?.status === 200 || f.confidence === "confirmed").length;

  const summary = buildSummary(normalized);
  summary.error_count = errors.length;

  const now = new Date().toISOString();

  // Detect timeout: if --timeout fired, AbortErrors will appear in the errors array.
  const timedOut = errors.some(
    (e) => e.error && (e.error.includes("abort") || e.error.includes("timeout") || e.error.includes("AbortError"))
  );
  if (timedOut) {
    console.error("[timeout] --timeout exceeded; partial results returned");
  }

  // Resolve scanned counts (column grants overwrites table column count per original logic)
  const nColumnsScanned = state.nColumnGrants !== null ? state.nColumnGrants : state.nTableColumns;
  const rpcFunctions = state.rpcFunctions;
  const rpcConfirmed = state.rpcConfirmed;
  const rpcInferred = state.rpcInferred;
  const nBucketsScanned = state.nBucketsScanned;
  const nEdgeFunctionsScanned = state.nEdgeFunctionsScanned;
  const nExtensionsScanned = state.nExtensionsScanned;
  const exposedSchemas = state.exposedSchemas;
  const ownersWithLeak = state.ownersWithLeak;
  const funcs = state.funcs;
  const tables = state.tables;

  const result = {
    schema_version: "1.0",
    project_ref: ref,
    project_name: meta.name || ref,
    region: meta.region || "unknown",
    generated_at: now,
    mode: activeProbe ? "audit-active" : "audit-passive",
    summary,
    findings: normalized,
    scan_complete: errors.length === 0,
    scan_failures: errors.map((e) => e.check),
    db_version: dbVersion,
    errors,
    active_probe: { enabled: probeAvailable, probed, confirmed, auth_user_signed_up: !!userJwt },
    rpc_probe: { enabled: probeAvailable, scanned: rpcFunctions.length, confirmed: rpcConfirmed, inferred: rpcInferred },
    n_tables_scanned: tables.length,
    n_functions_scanned: funcs.length,
    n_edge_functions_scanned: nEdgeFunctionsScanned,
    n_buckets_scanned: nBucketsScanned,
    n_columns_scanned: nColumnsScanned,
    n_extensions_scanned: nExtensionsScanned,
    n_schemas_scanned: exposedSchemas.length,
    schemas_scanned: state.scanSchemas ? state.scanSchemas.length : exposedSchemas.length,
    exposed_schemas: exposedSchemas,
    history: state.history || null,
    timed_out: timedOut,
    // Backward-compat aliases
    scanned_at: now,
    scanned_by: "supabase-security v0.4",
    stale_suppressions: staleSuppressions,
  };

  // Backward-compat aliases for report.js / action.yml consumers
  result.summary.critical = result.summary.by_severity.critical;
  result.summary.high = result.summary.by_severity.high;
  result.summary.medium = result.summary.by_severity.medium;
  result.summary.low = result.summary.by_severity.low;
  result.summary.info = result.summary.by_severity.info;

  // Self-validate: exit 12 if our own output violates the schema
  const validation = validate(result, SCHEMA);
  if (!validation.valid) {
    throw Object.assign(new Error(`Schema validation failed: ${JSON.stringify(validation.errors)}`), {
      code: "SCHEMA_VIOLATION",
    });
  }

  // Self-validate: exit 12 if secrets leaked into output
  const secrets = scanForSecrets(JSON.stringify(result));
  if (secrets.length > 0) {
    throw Object.assign(
      new Error(`SECRET LEAK DETECTED in output: ${JSON.stringify(secrets)}`),
      { code: "SCHEMA_VIOLATION" }
    );
  }

  return result;
}

// === HTML opt-in (spec entry 3) ===

/**
 * Resolve the output mode from CLI args + TTY state.
 * - --html <path> → always write HTML to that path
 * - --json (or non-TTY) → JSON only, no prompt
 * - TTY + no --html/--json → prompt interactively for HTML
 *
 * @param {string[]} args — raw argv (without node + script)
 * @param {boolean} isTTY — whether stdin is a TTY (interactive)
 * @returns {{ mode: 'html'|'json'|'prompt', htmlPath: string|null }}
 */
export function resolveOutputMode(args, isTTY = false) {
  const htmlIdx = args.indexOf("--html");
  if (htmlIdx !== -1) {
    return { mode: "html", htmlPath: args[htmlIdx + 1] || "report.html" };
  }
  if (args.includes("--json") || !isTTY) {
    return { mode: "json", htmlPath: null };
  }
  // TTY without --html or --json: prompt the user
  return { mode: "prompt", htmlPath: null };
}

/** Interactive y/N confirmation (TTY only). Returns the raw answer string. */
function promptConfirm(message) {
  const rl = createInterface({ input: process.stdin, output: process.stdout });
  return new Promise((resolve) => {
    rl.question(message, (answer) => {
      rl.close();
      resolve(answer.trim().toLowerCase());
    });
  });
}

// CLI
async function main() {
  const args = process.argv.slice(2);
  if (args.includes("--help") || args.includes("-h")) {
    console.error(`Usage:
  Full audit (needs Personal Access Token):
    SUPABASE_ACCESS_TOKEN=sbp_xxx node scripts/audit.js <project-ref> [--json|--html report.html] [--no-probe] [--fail-on high]

  Flags:
    --json          Output JSON to stdout (default; pipe to validate.js)
    --html <path>   Write an HTML report to <path> (JSON is always emitted to stdout)
    --no-probe      NO-OP alias (kept for back-compat). Active probing is OFF by default; use --probe to enable.
    --probe         Enable active anon-key probe (OPT-IN — POSTs to RPC/storage and signs up a temp user). Default: off (passive, read-only).
    --probe-volatile  Allow probing of VOLATILE RPCs (provolatile='v'). By default, volatile functions are reported as inferred-only (never executed). STABLE/IMMUTABLE functions remain probeable with --probe.
    --history         Enable historical-exposure scan via pg_stat_statements: reports queries that anon/authenticated actually executed (rows > 0 = confirmed data access, not just potential). Defaults OFF; --probe not required.
    --trace         Log every Management-API query, HTTP status, and probe to stderr (never secrets)
    --fail-on <sev> Exit 2 if any finding at/above this severity (critical|high|medium|low|info|never). Default: high
    --confirmed-only  Only count confidence===confirmed findings toward the exit-code gate (inferred findings still reported). Default: off — both confirmed and inferred count.
    --baseline <path>  Write a signed baseline (first run) or diff against it (subsequent runs). New findings vs baseline at/above --fail-on fail the gate.
    --timeout <sec>   Abort all probes + SQL queries after this many seconds (scaling safety on large projects). Default: 0 (no limit)
    --token <tok>   Supabase Personal Access Token (or SUPABASE_ACCESS_TOKEN env)
    --discover [path]   Keyless static repo scan + anon-only probe
    --include-system-schemas  Include Supabase platform schemas (storage, realtime, auth, vault, etc.) in enumeration. Default: off — vendor-controlled schemas are excluded.

  Exit codes:
    0  Clean — no findings at/above --fail-on severity
    2  Findings — one or more findings at/above --fail-on severity
    10 Auth error — token rejected (401/403)
    11 Network error — DNS/connection failure
    12 Tool error — own output failed schema validation or secret-leak scan

  Canonical test command: node --test   (never: node --test test/)`);
    process.exit(0);
  }

  if (args.length === 0) {
    console.error("Error: provide a project ref or --help");
    process.exit(1);
  }

  // --discover mode (v0.4): no PAT required, parses repo + probes anonymously.
  if (args.includes("--discover")) {
    const { discover } = await import("./discover.js");
    const idx = args.indexOf("--discover");
    const path = args[idx + 1] && !args[idx + 1].startsWith("--") ? args[idx + 1] : process.cwd();
    const result = await discover({ root: path });

    const discoverOutputMode = resolveOutputMode(args, process.stdin.isTTY);

    // JSON is the PRIMARY contract — always emit to stdout.
    console.log(JSON.stringify(result, null, 2));

    if (discoverOutputMode.mode === "html") {
      const { renderHtml } = await import("./report.js");
      writeFileSync(discoverOutputMode.htmlPath, renderHtml(result));
      console.error(`Discover report written to ${discoverOutputMode.htmlPath}`);
    } else if (discoverOutputMode.mode === "prompt") {
      const answer = await promptConfirm("\nGenerate HTML report? [y/N]: ");
      if (answer === "y" || answer === "yes") {
        const { renderHtml } = await import("./report.js");
        writeFileSync("discover-report.html", renderHtml(result));
        console.error("HTML report written to discover-report.html");
      }
    }
    process.exit(0);
  }

  const ref = args[0];
  if (ref.startsWith("--")) {
    console.error("Error: provide a project ref as the first argument");
    process.exit(1);
  }

  const token = process.env.SUPABASE_ACCESS_TOKEN || (args.includes("--token") ? args[args.indexOf("--token") + 1] : null);
  if (!token) {
    console.error("Error: provide SUPABASE_ACCESS_TOKEN env var or --token flag (Personal Access Token from supabase.com/dashboard/account/tokens)");
    console.error("\nTip: try --discover for a keyless scan of your local repo:");
    console.error("  node scripts/audit.js --discover .");
    process.exit(10);
  }

  const activeProbe = args.includes("--probe");
  // --no-probe accepted as a no-op alias so existing CI/scripts don't break.
  const probeVolatile = args.includes("--probe-volatile");
  const historyEnabled = args.includes("--history");
  const traceEnabled = args.includes("--trace");
  if (traceEnabled) setTrace(true);
  const failOnArg = args.includes("--fail-on") ? args[args.indexOf("--fail-on") + 1] : "high";
  const failOn = failOnArg;
  const confirmedOnly = args.includes("--confirmed-only");
  const includeSystemSchemas = args.includes("--include-system-schemas");
  const baselineArg = args.includes("--baseline") ? args[args.indexOf("--baseline") + 1] : null;
  const timeoutArg = args.includes("--timeout") ? parseInt(args[args.indexOf("--timeout") + 1], 10) : 0;

  // Set up the abort signal for --timeout (spec entry 6 scaling fix).
  // When fired, all in-flight fetch calls are aborted.
  setTimeoutSignal(timeoutArg);

  try {
    const suppressions = loadSuppressions(process.cwd());
    const result = await audit(token, ref, { activeProbe, probeVolatile, historyEnabled, suppressions, includeSystemSchemas });

    // Warn about stale suppressions (allowlisted items that no longer fire).
    if (result.stale_suppressions && result.stale_suppressions.length > 0) {
      console.error(`WARNING: ${result.stale_suppressions.length} stale suppression(s) in .supa360.json — allowlisted item(s) no longer found:`);
      for (const s of result.stale_suppressions) {
        console.error(`  - ${s.target}${s.check ? ` (${s.check})` : ""}: ${s.reason || "no reason given"}`);
      }
    }

    const outputMode = resolveOutputMode(args, process.stdin.isTTY);

    // JSON is the PRIMARY contract — always emit it to stdout (agent-first).
    console.log(JSON.stringify(result, null, 2));

    if (outputMode.mode === "html") {
      const { renderHtml } = await import("./report.js");
      writeFileSync(outputMode.htmlPath, renderHtml(result));
      console.error(`HTML report written to ${outputMode.htmlPath}`);
      console.error(`Findings: ${result.summary.by_severity.critical} critical, ${result.summary.by_severity.high} high, ${result.summary.by_severity.medium} medium${result.active_probe.enabled ? ` (${result.active_probe.confirmed} CONFIRMED via active probe)` : ""}`);
    } else if (outputMode.mode === "prompt") {
      // Interactive TTY without --html: ask if the user wants an HTML report.
      const answer = await promptConfirm("\nGenerate HTML report? [y/N]: ");
      if (answer === "y" || answer === "yes") {
        const { renderHtml } = await import("./report.js");
        writeFileSync("report.html", renderHtml(result));
        console.error("HTML report written to report.html");
      }
    }

    // --- Baseline + diff mode (entry 28) ---
    let baseline = null;
    if (baselineArg) {
      if (!baselineExists(baselineArg)) {
        // First run: write a signed baseline of accepted findings
        const savedBaseline = saveBaseline(baselineArg, result);
        console.error(`Baseline written to ${baselineArg} (${Object.keys(savedBaseline.findings).length} findings accepted)`);
        return EXIT_CODES.CLEAN;
      } else {
        // Subsequent run: diff against baseline, mark regressions
        baseline = loadBaseline(baselineArg);
        const { newFindings, existingFindings, removedFindings } = diffBaseline(baseline, result);
        result.baseline_diff = buildBaselineDiff(baseline, newFindings, existingFindings, removedFindings);

        if (result.baseline_diff.regression) {
          console.error(`REGRESSION: ${newFindings.length} new finding(s) vs baseline at ${baselineArg}`);
        }
      }
    }

    const exitCode = baseline
      ? computeBaselineExitCode({ errors: {}, result, baseline, failOn, confirmedOnly })
      : computeExitCode({ errors: {}, result, failOn, confirmedOnly });
    return exitCode;
  } catch (e) {
    if (e instanceof AuthError) {
      console.error(e.message);
      return EXIT_CODES.AUTH_ERROR;
    }
    const classification = classifyError(e);
    if (classification === "auth_error") {
      console.error(e.message);
      return EXIT_CODES.AUTH_ERROR;
    }
    if (classification === "network_error") {
      console.error(e.message);
      return EXIT_CODES.NETWORK_ERROR;
    }
    if (e.code === "SCHEMA_VIOLATION") {
      console.error(e.message);
      return EXIT_CODES.SCHEMA_VIOLATION;
    }
    console.error(e.message);
    return 1;
  } finally {
    // WO-1c: Always tear down the probe user (if one was created) — even when
    // the audit throws. This prevents orphan accounts in auth.users.
    // Only runs when --probe was passed (activeProbe === true), because
    // signupTestUser is only called when activeProbe is true.
    if (activeProbe && token && _probeUserJwt) {
      await cleanupProbeUser(token, ref);
    }
  }
}

// Guard process.argv[1] for safe import as a library (e.g. from tests or lab.js).
const argv1 = process.argv[1] || "";
if (import.meta.url === `file://${argv1.replace(/\\/g, "/")}` || (argv1 && import.meta.url.endsWith(argv1.replace(/\\/g, "/")))) {
  main().then((exitCode) => {
    process.exit(exitCode ?? 0);
  }).catch((e) => {
    console.error(e?.message || e);
    process.exit(1);
  });
}

export { audit, sql, getAnonKey, probeAnonAccess, signupTestUser, probeAuthenticatedAccess, main }; // resolveOutputMode + promptConfirm + cleanupProbeUser exported via their declarations above
