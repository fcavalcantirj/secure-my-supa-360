// Column-level grant + non-public exposed-schema analyzer (pure, DB-free).
//
// Spec entry 13 (coverage-schema-grants):
//  - Audit EVERY exposed schema (public, graphql_public, custom) via the
//    PostgREST db_schema config, not just public.
//  - Enumerate column-level anon/authenticated SELECT grants that expose
//    sensitive columns — even when table-level access is denied (the
//    classic column-grant bypass that table-level-only audits miss).
//  - Flag custom schemas exposed via the Data API that shouldn't be.
//
// Mirrors scripts/checks/rls.js + storage.js + views.js: feed in structured
// rows from pg_attribute/pg_namespace and get findings out — zero live DB needed.

import { isSensitiveColumn } from "./pii.js";
// Re-export so existing imports (test/grants.test.js) keep working.
export { isSensitiveColumn };

// Schemas that are safe to expose by default (Supabase/PostgREST built-ins + public).

// Schemas that are safe to expose by default (Supabase/PostgREST built-ins + public).
const KNOWN_SAFE_SCHEMAS = new Set([
  "public",
  "graphql_public",
  "pg_catalog",
  "information_schema",
  "pg_toast",
  "pg_temp",
  "pg_toast_temp",
]);

// Internal Postgres schemas that should never be flagged.
const INTERNAL_SCHEMA_RE = /^(_pg|pg_toast|pg_temp)/;

/**
 * Classify a single column-level grant row into a finding (or null).
 *
 * A column-level SELECT grant matters ONLY when it bypasses a locked table: the
 * role can read the column while lacking table-level SELECT. That is the whole
 * point of this check.
 *
 * CRITICAL SEMANTICS — has_column_privilege() returns TRUE whenever the role holds
 * a TABLE-level grant (PostgreSQL: a table grant implies every column). So
 * `*_col_select` alone does NOT mean "a column-level grant exists". Treating it as
 * such made this check emit one finding per readable column of every readable table:
 * on a real project, 160 of 160 CRITICALs were tables the role could already read
 * in full, and each shipped a `REVOKE SELECT(col)` fix that is a documented no-op
 * while the table grant stands. Zero were the bypass this check exists to find.
 *
 * The bypass test is per ROLE: colPriv && !tablePriv. It must NOT be computed as
 * `anonTable || authTable` — an `authenticated` table grant would then mask a real
 * `anon` column-level bypass, which is a false negative in the dangerous direction.
 *
 * Severity (bypass cases only):
 * - critical: sensitive column (PII/credentials) readable while the table is locked
 * - high: non-sensitive column readable while the table is locked
 * Columns already covered by a table-level grant are NOT reported here — that
 * exposure belongs to the RLS/table-grant checks, which evaluate row policies.
 *
 * @param {object} row — {
 *   schema_name, table_name, column_name, data_type,
 *   anon_col_select (bool), auth_col_select (bool),
 *   anon_table_select (bool), auth_table_select (bool)
 * }
 * @returns {object|null} finding or null
 */
export function classifyColumnGrant(row) {
  const anonCol = !!row.anon_col_select;
  const authCol = !!row.auth_col_select;
  if (!anonCol && !authCol) return null;
  if (!row.column_name) return null;

  const anonTable = !!row.anon_table_select;
  const authTable = !!row.auth_table_select;

  // Per-role bypass: the role can read this column WITHOUT table-level SELECT.
  // Evaluated per role on purpose — see the header note on false negatives.
  const anonBypass = anonCol && !anonTable;
  const authBypass = authCol && !authTable;

  const roles = [];
  if (anonBypass) roles.push("anon");
  if (authBypass) roles.push("authenticated");

  // No bypass for any role => the column is readable only because the TABLE is
  // readable. Revoking the column grant would be a no-op, and the exposure is the
  // table-grant/RLS checks' to report. Staying silent here keeps CRITICAL meaningful.
  if (roles.length === 0) return null;

  const sensitive = isSensitiveColumn(row.column_name, row.data_type);
  const severity = sensitive ? "critical" : "high";

  return {
    check: "column_grant_exposes_column",
    category: "coverage-schema-grants",
    severity,
    confidence: "inferred",
    target: `column:schema:${row.schema_name}:table:${row.table_name}:col:${row.column_name}`,
    evidence: {
      schema_name: row.schema_name,
      table_name: row.table_name,
      column_name: row.column_name,
      data_type: row.data_type,
      roles_exposed: roles,
      // Always false now, and kept for report/consumer compatibility: a role is only
      // reported here when it LACKS table-level SELECT. Read the per-role fields below
      // for the full picture (another role may well hold the table grant).
      table_level_select: false,
      // Per-role privileges, so a reader can falsify this finding without re-querying.
      anon_column_select: anonCol,
      anon_table_select: anonTable,
      authenticated_column_select: authCol,
      authenticated_table_select: authTable,
      column_level_select: true,
      sensitive,
      reason: `${roles.join(" + ")} can SELECT this column while lacking table-level SELECT on ${row.schema_name}.${row.table_name} — a column grant bypassing the table lock`,
    },
    fix: {
      sql: [
        `-- Revoke the column-level SELECT grant so this column respects table-level RLS:`,
        `REVOKE SELECT(${row.column_name}) ON ${row.schema_name}.${row.table_name} FROM ${roles.join(", ")};`,
      ],
      rollback_sql: [
        `GRANT SELECT(${row.column_name}) ON ${row.schema_name}.${row.table_name} TO ${roles.join(", ")};`,
      ],
      dashboard_action: null,
      management_api_action: null,
      requires_service_role: false,
    },
  };
}

/**
 * Identify custom schemas exposed via the PostgREST db_schema config that
 * shouldn't be. Known safe schemas (public, graphql_public, system schemas)
 * are skipped. Any other schema is flagged as a potential exposure.
 *
 * @param {string[]} schemas — schema names from the PostgREST db_schema config
 * @returns {object[]} findings (may be empty)
 */
export function findExposedSchemas(schemas) {
  if (!Array.isArray(schemas)) return [];
  const findings = [];
  for (const schema of schemas) {
    if (!schema) continue;
    const trimmed = String(schema).trim();
    if (!trimmed) continue;
    if (KNOWN_SAFE_SCHEMAS.has(trimmed)) continue;
    // WO-7: filter Postgres search_path placeholders ($user, $myvar_schema, etc.)
    // — these are NOT schema names and would cause false positives.
    if (trimmed.startsWith("$")) continue;
    if (INTERNAL_SCHEMA_RE.test(trimmed)) continue;

    findings.push({
      check: "custom_schema_exposed",
      category: "coverage-schema-grants",
      severity: "low",
      confidence: "inferred",
      target: `schema:${trimmed}`,
      evidence: {
        schema_name: trimmed,
        reason: "Custom schema is exposed via the PostgREST db_schema config",
      },
      fix: {
        sql: [
          `-- Remove "${trimmed}" from the PostgREST db_schema setting so it is no longer exposed via the REST/Data API.`,
        ],
        rollback_sql: [
          `-- Rollback: re-add "${trimmed}" to the PostgREST db_schema setting (Dashboard -> Project Settings -> Data API).`,
        ],
        dashboard_action:
          "Dashboard -> Project Settings -> Data API -> remove the custom schema from 'Exposed schemas'",
        management_api_action: null,
        requires_service_role: false,
      },
    });
  }
  return findings;
}

/**
 * Process an array of column-level grant rows and return findings.
 * Synchronous — column grants are config-level, no active probe needed.
 *
 * @param {object[]} rows — column grant rows from the SQL query
 * @returns {object[]}
 */
export function processColumnGrants(rows) {
  const findings = [];
  for (const row of rows) {
    const f = classifyColumnGrant(row);
    if (f) findings.push(f);
  }
  return findings;
}
