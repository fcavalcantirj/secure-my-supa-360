---
name: supabase-security
description: "Agent-driving 360° Supabase security auditor. Scans RLS, RPC, storage, auth, network, extensions, realtime, data-api, secrets — and ACTIVELY PROBES each leak with the anon key to confirm it, not just infer it. Zero deps, runs locally, token never leaves your machine."
metadata:
  author: fcavalcantirj
  version: "0.4.2"
  homepage: https://github.com/fcavalcantirj/secure-my-supa-360
---

# Supabase Security Skill (360° Auditor)

A pure-Node.js audit + remediation toolkit for Supabase projects — **zero dependencies, runs locally, your token never leaves your machine.** Passive metadata scan by default (read-only); `--probe` opt-in for live confirmation. **70 checks** across 15 categories.

## What it checks (70 checks)

Each finding is classified as **confirmed** (a live probe proved the leak) or **inferred** (metadata/grant analysis only). Active probing (`--probe`) POSTs to RPC/storage endpoints and signs up a temporary auth user — it is OPT-IN and automatically tears down the probe user on exit. Default mode is **passive** (read-only metadata scan, no network writes).

### coverage-rls — Row Level Security + default privileges (6 checks, **access-closing**)

These checks close data-access holes: each fix REVOKEs anon/authenticated grants or
enables/rewrites RLS policies so anon can no longer read or write the table.

| Check ID | Severity | Confidence | How | Fix Type | Rollback | Restore-From-Captured |
|---|---|---|---|---|---|---|
| `rls_disabled` | CRITICAL | inferred | Table in RLS OFF + anon/auth grants | SQL | Yes | Yes (exact: toggle RLS off) |
| `rls_permissive_policy` | HIGH → CRITICAL | confirmed if probe leaks | RLS ON but `USING (true)` or unscoped policy + anon grants | SQL | Yes | Yes (exact: original policy qual) |
| `rls_permissive_write_policy` | HIGH | inferred | INSERT/UPDATE policy with permissive/missing/unscoped `WITH CHECK` + anon grants | SQL | Yes | Yes (exact: original WITH CHECK) |
| `rls_with_check_divergence` | MEDIUM | inferred | `USING` and `WITH CHECK` differ on UPDATE/ALL | SQL | Yes | Yes (exact: original WITH CHECK) |
| `rls_no_policies_with_anon_grants` | LOW | inferred | RLS locked but direct anon grants remain | SQL | Yes | Yes (exact: original GRANT) |
| `default_privileges_not_revoked` | MEDIUM | inferred | Future tables auto-exposed to anon/auth via default ACLs. **WO-10**: only flags data-access privileges (SELECT/INSERT/UPDATE/DELETE), not MAINTAIN/TRIGGER | SQL (postgres) / Dashboard (supabase_admin) | Yes (postgres) / No (supabase_admin) | Yes (exact: captured ACL) / No (dashboard) |

### rls-performance — RLS policy performance (4 checks, **performance only — does NOT close security holes**)

These are performance optimizations, not access-closing fixes. **Only one of six
practices actually closes a hole** — `rls_permissive_policy` (revoke the permissive
policy). The four below improve query speed but do not change who can access data.
They are reported so agents don't ship slow per-row policy evaluation, but they
are excluded from `--confirmed-only` gates and `--fail-on` when no access-closing
finding exists.

| Check ID | Severity | Confidence | How | Fix Type | Rollback | Restore-From-Captured |
|---|---|---|---|---|---|---|
| `rls_unwrapped_auth_fn` | MEDIUM | inferred | Policy calls `auth.uid()` / `auth.jwt()` / `current_setting()` unwrapped instead of `(select auth.uid())` — re-executes per row, defeating the initPlan cache | SQL | Yes | Yes (exact: original policy qual) |
| `rls_unindexed_policy_column` | MEDIUM → HIGH (large tables) | inferred | Policy column used in equality predicate against auth value has no btree index | SQL (CREATE INDEX) | Yes (DROP INDEX) | Yes (index name from catalog) |
| `rls_policy_join` | MEDIUM | inferred | Policy contains `EXISTS(SELECT ...)` or correlated `IN (SELECT ...)` — re-executes the subquery for every row | Dashboard (rewrite to secdef fn) | No | No (manual rewrite) |
| `rls_policy_public_role` | LOW | inferred | Policy grants role `{public}` (no explicit `TO authenticated`) — forces anon pre-evaluation | SQL | Yes | Yes (exact: original roles list) |

### coverage-rpc — Functions / RPC (7 checks)

| Check ID | Severity | Confidence | How | Fix Type | Rollback | Restore-From-Captured |
|---|---|---|---|---|---|---|
| `function_security_definer_anon_executable` | HIGH | inferred | SECURITY DEFINER function callable by anon | SQL (REVOKE EXECUTE) | Yes | Yes (exact: original GRANT) |
| `function_no_search_path` | MEDIUM | inferred | Any SECURITY DEFINER fn without `SET search_path` | SQL (ALTER FUNCTION) | Yes | Yes (exact: original config) |
| `function_secdef_missing_auth_check` | CRITICAL | inferred | SECURITY DEFINER fn with no internal `auth.uid()/auth.role()/current_setting` check | SQL (edit body) | Yes (manual body revert) | Yes (manual: see note) |
| `function_secdef_no_search_path` | MEDIUM | inferred | SECURITY DEFINER fn without `SET search_path` (shadow risk) | SQL (ALTER FUNCTION) | Yes | Yes (exact: original config) |
| `function_secdef_dynamic_sql` | HIGH | inferred | Dynamic SQL from args without `%I`/`%L`/`USING` quoting | SQL (edit body) | Yes (manual body revert) | Yes (manual: see note) |
| `rpc_confirmed_executable` | HIGH → CRITICAL | **confirmed** | Active probe POST'd to `/rest/v1/rpc/<fn>` and the body executed | SQL (REVOKE EXECUTE) | Yes | Yes (exact: original GRANT) |
| `rpc_granted_inferred` | LOW | inferred | Anon EXECUTE grant exists but probe was blocked/gated | SQL (REVOKE EXECUTE) | Yes | Yes (exact: original GRANT) |

### coverage-views — Views (2 checks)

| Check ID | Severity | Confidence | How | Fix Type | Rollback | Restore-From-Captured |
|---|---|---|---|---|---|---|
| `view_security_definer_bypass` | HIGH → CRITICAL | confirmed if probe leaks | View with `security_invoker=false` over RLS-locked base table | SQL (ALTER VIEW) | Yes | Yes (exact: original setting) |
| `view_exposes_pii_to_anon` | CRITICAL | inferred | Anon-SELECTable view includes PII columns (cpf, email, phone, etc.) | SQL (edit view + GRANT) | Yes (view recreation) | Yes (exact: original view def) |

### coverage-storage — Buckets / storage.objects (6 checks)

| Check ID | Severity | Confidence | How | Fix Type | Rollback | Restore-From-Captured |
|---|---|---|---|---|---|---|
| `storage_bucket_public` | HIGH | inferred | Bucket with `public = true` | SQL (UPDATE storage.buckets) | Yes | Yes (exact: original public flag) |
| `storage_bucket_misconfigured` | MEDIUM | inferred | Missing file size limit or MIME type restrictions (incl. `*/*`) | SQL (UPDATE storage.buckets) | Yes | Yes (exact: original config) |
| `storage_objects_anon_read` | HIGH | confirmed if probe returns rows | Anon SELECT on storage.objects (object read leak) | SQL (REVOKE SELECT) | Yes | Yes (exact: original GRANT) |
| `storage_objects_anon_insert` | CRITICAL | confirmed | Anon INSERT on storage.objects (arbitrary upload) | SQL (REVOKE INSERT) | Yes | Yes (exact: original GRANT) |
| `storage_objects_anon_tamper` | CRITICAL | confirmed | Anon UPDATE/DELETE on storage.objects (tamper / wipe) | SQL (REVOKE UPDATE/DELETE) | Yes | Yes (exact: original GRANT) |
| `storage_policy_unscoped_path` | MEDIUM | inferred | Storage policy lacks path/foldername scoping | SQL (rewrite policy) | Yes | Yes (exact: original policy qual) |

### coverage-auth — Auth configuration (9 checks)

| Check ID | Severity | Confidence | How | Fix Type | Rollback | Restore-From-Captured |
|---|---|---|---|---|---|---|
| `auth_signups_enabled_no_confirm` | MEDIUM | inferred | Signups open + autoconfirm on | Management API (PATCH) / Dashboard | Yes | Yes (exact: original settings) |
| `anonymous_signins_enabled` | HIGH | inferred | Anonymous sign-ins enabled | Management API (PATCH) | Yes | Yes (exact: original setting) |
| `weak_password_policy` | MEDIUM | inferred | Password minimum length < 8 | Management API (PATCH) | Yes | Yes (exact: original length) |
| `no_captcha_on_auth` | MEDIUM | inferred | CAPTCHA disabled on auth endpoints | Management API (PATCH) / Dashboard | Yes | Yes (exact: original config) |
| `auth_hibp_disabled` | MEDIUM | inferred | HIBP password breach checking disabled | Management API (PATCH) | Yes | Yes (exact: original setting) |
| `auth_otp_expiry_too_long` | MEDIUM | inferred | Emailed OTP expiry above the 3600s the Supabase Production Checklist recommends — widens the window an intercepted mail stays usable | Management API (`mailer_otp_exp: 3600`) | Yes | Yes (exact: prior value) |
| `auth_no_custom_smtp` | MEDIUM | inferred | No custom SMTP: auth mail comes from Supabase's shared sender (users cannot verify the domain) and is rate limited, default 2/hour | Dashboard only (needs YOUR provider credentials) | No | n/a |
| `auth_mfa_disabled` | HIGH | inferred | MFA not enforced | Dashboard | Yes | Yes (dashboard toggle) |
| `auth_jwt_exp_too_long` | MEDIUM | inferred | JWT expiration > 8 hours (28800s) | Management API (PATCH) | Yes | Yes (exact: original exp) |
| `auth_redirect_allowlist_open` | HIGH | inferred | Empty URI allowlist (open redirect) | Management API (PATCH) | Yes | Yes (exact: original list) |
| `auth_rate_limit_missing` | MEDIUM | inferred | No `rate_limit_*` config set | Management API (PATCH) | Yes | Yes (exact: original values) |

### coverage-schema-grants — Column & schema grants (2 checks)

| Check ID | Severity | Confidence | How | Fix Type | Rollback | Restore-From-Captured |
|---|---|---|---|---|---|---|
| `column_grant_exposes_column` | CRITICAL | inferred | Column-level SELECT grant on a sensitive column to anon/authenticated | SQL (REVOKE COLUMN) | Yes | Yes (exact: original GRANT) |
| `custom_schema_exposed` | LOW | inferred | Non-standard schema in PostgREST `db_schema` config | Management API (PATCH) | Yes | Yes (exact: original db_schema) |

### coverage-edge-functions — Edge Functions (4 checks)

| Check ID | Severity | Confidence | How | Fix Type | Rollback | Restore-From-Captured |
|---|---|---|---|---|---|---|
| `edge_function_verify_jwt_disabled` | HIGH | inferred | Function has `verify_jwt = false` (publicly invokable) | Management API (PATCH) | Yes | Yes (exact: original verify_jwt) |
| `edge_function_wildcard_cors` | MEDIUM | inferred | Wildcard CORS (`Access-Control-Allow-Origin: *`) | Management API (PATCH) | Yes | Yes (exact: original CORS) |
| `edge_function_secret_echo` | HIGH | inferred | Function reads secrets and logs/returns them | Source edit | Yes (manual) | Yes (manual: revert source) |
| `edge_function_unauthenticated_write` | CRITICAL | inferred | verify_jwt disabled + write operations (insert/update/delete) | Source edit + Management API | Yes (partial) | Yes (manual: revert source + toggle verify_jwt) |

### coverage-network-db — Network / DB config (3 checks)

| Check ID | Severity | Confidence | How | Fix Type | Rollback | Restore-From-Captured |
|---|---|---|---|---|---|---|
| `db_no_network_restrictions` | MEDIUM → HIGH (prod) | inferred | Direct Postgres (5432) reachable without IP allowlist | Management API (PATCH) | Yes | Yes (exact: original restrictions) |
| `db_ssl_disabled` | MEDIUM → HIGH (prod) | inferred | SSL/TLS not enforced for Postgres connections | Management API (PATCH) | Yes | Yes (exact: original ssl setting) |
| `db_pool_session_mode` | LOW | inferred | Connection pooler in 'session' mode (incompatible with serverless) | Management API (PATCH) | Yes | Yes (exact: original pool_mode) |

### coverage-extensions-cron — Extensions / cron / Vault (4 checks)

| Check ID | Severity | Confidence | How | Fix Type | Rollback | Restore-From-Captured |
|---|---|---|---|---|---|---|
| `extension_risky_installed` | MEDIUM | inferred | Extension (http / pg_net) reachable by low-priv roles (SSRF) | SQL (DROP EXTENSION) | Yes | Yes (re-INSTALL) |
| `extension_known_vulnerable` | HIGH | inferred | Extension at a known-vulnerable version (CVEs) | SQL (UPDATE EXTENSION) | Yes | Yes (exact: original version) |
| `cron_job_embedded_secret` | HIGH | inferred | pg_cron job command contains an embedded secret | SQL (UPDATE cron.job) | Yes | Yes (exact: original command) |
| `vault_decrypted_secrets_exposed` | CRITICAL | inferred | `vault.decrypted_secrets` readable by anon/authenticated | SQL (REVOKE SELECT) | Yes | Yes (exact: original GRANT) |

### coverage-realtime — Realtime (3 checks)

| Check ID | Severity | Confidence | How | Fix Type | Rollback | Restore-From-Captured |
|---|---|---|---|---|---|---|
| `realtime_publication_no_rls` | CRITICAL | inferred | Table in `supabase_realtime` publication without RLS | SQL (ALTER PUBLICATION) | Yes | Yes (exact: original publication) |
| `realtime_broadcast_anon_read` | HIGH → LOW (RLS ON, 0 policies) | inferred | Anon can read realtime.messages | SQL (REVOKE SELECT) | Yes | Yes (exact: original GRANT) |
| `realtime_broadcast_anon_write` | CRITICAL → LOW (RLS ON, 0 policies) | inferred | Anon can write realtime.messages | SQL (REVOKE INSERT) | Yes | Yes (exact: original GRANT) |

### coverage-data-api — Data API (3 checks)

| Check ID | Severity | Confidence | How | Fix Type | Rollback | Restore-From-Captured |
|---|---|---|---|---|---|---|
| `data_api_auto_expose_on` | MEDIUM | inferred | "Automatically expose new tables" toggle is ON + Data API enabled + default privs grant anon/auth | Management API (PATCH) / Dashboard | Yes | Yes (exact: original toggle) |
| `data_api_many_functions_exposed` | LOW | inferred | Large anon-executable RPC surface via REST | SQL (REVOKE EXECUTE) | Yes | Yes (exact: original GRANT) |
| `data_api_disabled` | INFO | inferred | Data API (REST) is disabled — db_schema empty. Secure-by-default | N/A (no fix needed) | N/A | N/A |

### coverage-history — Historical exposure (3 checks, opt-in `--history`)

| Check ID | Severity | Confidence | How | Fix Type | Rollback | Restore-From-Captured |
|---|---|---|---|---|---|---|
| `anon_historical_read` | CRITICAL | confirmed | pg_stat_statements shows anon SELECT with rows>0 against a table currently holding data | SQL (REVOKE SELECT) | Yes | Yes (exact: captured ACL) |
| `anon_historical_write` | HIGH | confirmed | pg_stat_statements shows anon INSERT/UPDATE/DELETE executed with rows>0 | SQL (REVOKE INSERT/UPDATE/DELETE) | Yes | Yes (exact: captured ACL) |
| `anon_historical_enumeration` | HIGH → CRITICAL | confirmed | Anon LIMIT/OFFSET without WHERE returned rows — bulk table hoovering; escalates to critical when the table currently holds data | SQL (REVOKE SELECT) | Yes | Yes (exact: captured ACL) |

History findings are aggregated by (role, table, verb) into one finding per group with summed totals. Audit probe queries (tagged `/* supa360-probe */` or matching the legacy `SELECT * FROM … LIMIT 1` shape) and PostgREST internals (`set_config`, `obj_description`, system catalogs) are excluded from analysis.

### coverage-secrets — Committed secrets (7 checks, file scan)

| Check ID | Severity | Confidence | How | Fix Type | Rollback | Restore-From-Captured |
|---|---|---|---|---|---|---|
| `committed_service_role_jwt` | CRITICAL | inferred | Service-role JWT committed in source | Manual (rotate key) | No | No (manual: rotate + force-refresh) |
| `committed_supabase_pat` | CRITICAL | inferred | Supabase PAT (`sbp_...`) committed in source | Manual (revoke PAT) | No | No (manual: re-issue PAT) |
| `committed_supabase_secret` | HIGH | inferred | Supabase `supabase secret` value committed | Manual (rotate secret) | No | No (manual: re-issue secret) |
| `committed_db_connstring` | HIGH | inferred | Database connection string committed | Manual (rotate password) | No | No (manual: re-issue credentials) |
| `committed_thirdparty_key` | HIGH | inferred | Third-party API keys (AWS, Stripe, GitHub, etc.) committed | Manual (rotate key) | No | No (manual: rotate in 3rd-party dashboard) |
| `env_secret_exposed_to_browser` | HIGH | inferred | `NEXT_PUBLIC_*` env var contains a secret (exposed to browser) | Source edit | No | No (manual: revert + rotate) |
| `dotenv_tracked` | MEDIUM | inferred | `.env` file is git-tracked (secrets in git history) | `git rm --cached` + rotate all | No | No (manual: rotate + purge git history) |

### coverage-discover — Keyless repo scan (8 checks, discover mode)

| Check ID | Severity | Confidence | How | Fix Type | Rollback | Restore-From-Captured |
|---|---|---|---|---|---|---|
| `service_role_key_in_env_committed` | CRITICAL | inferred | Service role key in a tracked env file | Manual (rotate key) | No | No (manual) |
| `migration_missing_enable_rls` | MEDIUM | inferred | Migration creates a table without `enable_row_level_security` | SQL (ALTER TABLE ENABLE RLS) | Yes | Yes (exact: original RLS state) |
| `rls_enabled_no_policies` | MEDIUM | inferred | RLS on but zero policies = full lock (false sense of security) | SQL (CREATE POLICY) | Yes | Yes (DROP POLICY) |
| `table_leaks_via_anon` | CRITICAL | **confirmed** | Static probe of `/rest/v1/<table>?select=*` returns data as anon | SQL (REVOKE + CREATE POLICY) | Yes | Yes (exact: original grants + policy) |
| `bucket_listable_by_anon` | HIGH | inferred | Bucket listable by anon without policy | SQL (ALTER storage.buckets) / Management API | Yes | Yes (exact: original public flag) |
| `rpc_executes_for_anon` | CRITICAL | **confirmed** | RPC function executes for anon callers (static probe) | SQL (REVOKE EXECUTE) | Yes | Yes (exact: original GRANT) |
| `rpc_callable_signature_mismatch` | MEDIUM | inferred | RPC callable via REST but its signature doesn't match expected (hidden surface) | SQL (DROP FUNCTION) | Yes | Yes (exact: original function) |
| `rls_query_without_tenant_filter` | LOW | inferred | `.from('table').select()` on an RLS+policies table with no `.eq()` filter (best-effort heuristic) | Source edit (add .eq()) | No | No (manual: revert source) |

---

## CLI subcommands

```
supabase-security audit <ref> [flags]          Full audit (passive metadata scan; --probe for active confirmation)
supabase-security probe <ref> [flags]         Active-probe audit (alias for audit; --probe enabled by default)
supabase-security discover [path] [flags]     Keyless static repo scan (no PAT)
supabase-security remediate <result.json>     Consume a JSON result; dry-run by default
supabase-security verify <remediation.json>   Re-run audit after --apply to confirm closure
supabase-security report <file.json>          Render HTML from a prior JSON result
supabase-security help <subcommand>           Per-subcommand help
```

## Flags

| Flag | Applies to | Description |
|---|---|---|
| `--json` | all | Output JSON to stdout (default) |
| `--html <path>` | audit, probe, discover, report | Write HTML report to path |
| `--probe` | audit, probe | OPT-IN: enable active anon-key probe (POSTs to RPC/storage, signs up temp user). Default: OFF (passive, read-only mode). Use `--probe` to confirm leaks live |
| `--probe-volatile` | audit, probe | With --probe: also execute VOLATILE RPC functions (provolatile='v'). Without this flag, volatile functions are still reported but at confidence "inferred" (not probed — their side-effects can't be made safe). Requires --probe |
| `--history` | audit, probe | Enable historical-exposure scan via pg_stat_statements: reports anon/authenticated queries that actually returned data (rows>0 = confirmed data access). Requires pg_stat_statements extension |
| `--no-probe` | audit, probe | NO-OP alias (kept for backward compat). Active probing is OFF by default; use --probe to enable |
| `--fail-on <sev>` | audit, probe, discover | Exit 2 if findings at/above severity (default: `high` in CLI; `critical` in GitHub Action) |
| `--confirmed-only` | audit, probe | Only count `confidence === "confirmed"` findings toward the exit-code gate. Inferred-only findings (e.g. gated RPC grants) are still reported in JSON but don't fail CI. Default: off — both confirmed and inferred count |
| `--baseline <path>` | audit, probe | Write a signed baseline (first run) or diff against it (subsequent runs). New findings at/above `--fail-on` vs baseline are marked as regressions and fail the gate. Known findings don't re-trigger the gate. |
| `--timeout <sec>` | audit, probe | Abort all probes + SQL queries after this many seconds. Prevents hangs on large projects (189+ tables). Default: 0 (no limit) |
| `--trace` | audit, probe | Log every Management-API query + probe to stderr (tokens/redacted) |
| `--apply` | remediate | Execute fixes (dry-run is default — nothing happens without this) |
| `--rollback` | remediate | Rollback a prior --apply using its snapshot |
| `--yes` | remediate, verify | Skip interactive confirmation (required for non-TTY) |
| `--token <tok>` | audit, remediate, verify | PAT (or `SUPABASE_ACCESS_TOKEN` env var) |
| `--service-role <key>` | remediate | service_role JWT for findings with `requires_service_role=true` |

## Environment variables

| Variable | Required | Purpose |
|---|---|---|
| `SUPABASE_ACCESS_TOKEN` | audit/probe/remediate/verify | Supabase Personal Access Token (passive audit is read-only; --probe opt-in adds write side-effects, remediate --apply requires --yes) |
| `SUPABASE_DB_URL` | remediate direct-DB mode | Postgres connection string for direct-DB remediation (optional — Management API is the default) |
| `SUPABASE_SERVICE_ROLE_KEY` | remediate (for privileged fixes) | service_role JWT — only used for findings where `requires_service_role=true` |

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Clean — no findings at/above `--fail-on` severity |
| `2` | Findings — one or more findings at/above `--fail-on` severity |
| `10` | Auth error — token rejected (401/403) |
| `11` | Network error — DNS/connection failure |
| `12` | Tool error — own output failed schema validation or secret-leak scan |

Auth/network errors (10/11) take priority over findings (2). If your token is invalid, you get 10 even if findings exist.

## JSON contract (v1.0)

The default output is a versioned, schema-validated JSON document:

```jsonc
{
  "schema_version": "1.0",
  "project_ref": "abcdefgh1234567",
  "project_name": "MyApp",
  "region": "us-east-1",
  "generated_at": "2026-08-28T12:00:00.000Z",
  "mode": "audit-active",           // audit-active | audit-passive | discover
  "summary": {
    "by_severity": { "critical": 2, "high": 3, "medium": 1, "low": 0, "info": 0 },
    "confirmed": 1,                  // live-probe-confirmed
    "inferred": 5,                   // metadata-only
    "suppressed": 0,
    "error_count": 0
  },
  "findings": [
    {
      "id": "a1b2c3d4e5f6",
      "check": "rls_permissive_policy",
      "category": "coverage-rls",
      "severity": "critical",
      "confidence": "confirmed",   // confirmed | inferred
      "target": "a_sensitive_table",
      "evidence": { "rls_enabled": true, "anon_select": true },
      "probe": { "status": 200, "bytes": 512, "sample": { "row_count": 3, "columns": ["id","name"] } },
      "fix": {
        "sql": ["ALTER TABLE ... ENABLE ROW LEVEL SECURITY;"],
        "rollback_sql": ["ALTER TABLE ... DISABLE ROW LEVEL SECURITY;"],
        "dashboard_action": null,
        "management_api_action": null,
        "requires_service_role": false
      },
      "references": ["https://supabase.com/docs/guides/auth/row-level-security"],
      "suppressed": false,
      "suppressed_reason": null,
      "title": "RLS permissive policy allows public read",
      "explain": "Policy with USING(true) allows any caller to read all rows."
    }
  ],
  "errors": []
}
```

Every finding has:
- **`id`** — deterministic hash of `check:target` (stable across runs for diff/baseline)
- **`confidence`** — `confirmed` (live probe proved the leak) vs `inferred` (metadata-only)
- **`probe`** — live evidence: HTTP status, bytes returned, sample row count + columns
- **`fix`** — executable `sql[]` + `rollback_sql[]` (inverse), or `management_api_action`/`dashboard_action` when SQL can't fix it
- **`suppressed`** — intentional exposure via `.supa360.json` allowlist (still reported, auditable)

The full schema is at `schema/finding.schema.json` — validated on every run.

## End-to-end agent flow (unattended)

```
1. AUDIT
   supabase-security audit <ref> --fail-on critical --json > result.json
   # exit 0 = clean, exit 2 = findings, 10/11/12 = errors

2. READ
   # Agent reads result.json, checks summary.confirmed for live-proven leaks

3. REMEDIATE (dry-run first, then apply)
   supabase-security remediate result.json            # review the plan
   supabase-security remediate result.json --apply --yes  # execute (BEGIN/COMMIT per finding)

4. VERIFY
   supabase-security verify remediation.json
   # Re-runs probes; marks findings as fixed_confirmed / fixed_unverified / fixed_failed / needs_dashboard

5. (OPTIONAL) REPORT
   supabase-security report result.json --html report.html  # offline HTML
```

**Remediation safety guarantees:**
- Dry-run is the default (nothing mutates without `--apply`)
- `--apply` requires explicit `--yes` confirmation in non-TTY mode
- Refs in `SUPA360_PERMANENT_BLOCKED_REFS` can **never** be remediated or used as a lab — no flag or env combination unblocks them. **Put production refs here.**
- Refs in `SUPA360_BLOCKED_REFS` are disposable **lab** projects: blocked from `--apply`/`--rollback` unless `SUPA360_LAB_REF=<same ref>` **and** `--i-understand-this-is-destructive`. Never list production here — this tier is unblockable by ceremony.
- Both unset by default: the tool cannot know which of your projects is production, set them yourself
- Either tier can also be declared in a gitignored `.supa360.json` (`permanent_blocked_refs` / `blocked_refs`), UNIONed with the env vars; a malformed config is a hard error, never a silent loss of protection
- Before any mutation, a snapshot of current state is saved for reversibility
- Findings without `rollback_sql` are auto-skipped (reported as manual)
- Each finding is applied in its own `BEGIN; ... COMMIT;` — a failure rolls back only itself
- Idempotent: applying the same fix twice does not error

## Trust & secret handling

- **Token never persisted:** `SUPABASE_ACCESS_TOKEN` is used only for the current process's Management API calls. It is never written to disk, never appears in JSON output, never appears in HTML reports.
- **Secrets never in output:** `scanForSecrets` runs on every serialized result (JSON + HTML). Any finding containing a PAT, JWT, connstring, or API key is redacted at the `evidence` level before output.
- **`supabase_admin` privilege gaps:** Some findings (e.g. default privileges owned by `supabase_admin`) cannot be fixed via SQL — `postgres` is not a member of `supabase_admin`. These emit a `dashboard_action` instead of failing SQL. **Action required:** toggle the setting in the Supabase Dashboard (Data API → "Automatically expose new tables" = OFF).
- **`SUPABASE_DB_URL`:** Only used for direct-DB remediation mode (optional). When omitted, all fixes go through the Management API. The DB password is never logged or stored.

## Scan scope

| Flag | Effect |
|---|---|
| `--discover [path]` | Keyless static scan of a repo — no token, no project ref. |
| `--include-system-schemas` | Include Supabase platform schemas (`storage`, `realtime`, `auth`, `vault`, `pg_*`, `pgsodium`, `_realtime`, `_analytics`) in enumeration. **Default: off** — those are vendor-controlled, and the dedicated storage/realtime checks query their own tables directly, so excluding them loses no user-actionable finding. |

## Suppression (intentional exposure)

Create `.supa360.json` in your project root to suppress findings you've reviewed and intentionally accepted:

```jsonc
{
  "suppressions": [
    { "check": "storage_bucket_public", "target": "bucket:brand-assets", "reason": "Public CDN bucket, intentional" }
  ]
}
```

Suppressed findings still appear in the JSON output with `suppressed: true` and `suppressed_reason` set — they are auditable, not hidden.

## Running tests

Canonical command: `node --test` (auto-discovers all `test/*.test.js`). Do **not** use `node --test test/` — it is broken in this Node version (resolves the directory as a module).

The golden harness (`test/golden-harness.test.js`) is the regression gate: it runs the full audit → remediate → verify cycle against `fixtures/seed.sql` (a deliberately vulnerable state) with injected transports — no live DB required for the unit tests. A live run against a throwaway Supabase project is done with `lab matrix` (see the `lab` subcommand), not with a flag on the unit suite.
