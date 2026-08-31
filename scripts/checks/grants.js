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
 * A column-level SELECT grant is a finding when anon or authenticated has
 * SELECT on a specific column. This bypasses table-level checks — a table
 * may appear locked (no table-level SELECT) but still leak individual columns.
 *
 * Severity:
 * - critical: sensitive column (PII/credentials) exposed to anon/auth
 * - high: non-sensitive column where table-level SELECT is denied (true bypass)
 * - medium: non-sensitive column where table-level is already granted (redundant)
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
  const tableLevelGranted = anonTable || authTable;

  const roles = [];
  if (anonCol) roles.push("anon");
  if (authCol) roles.push("authenticated");

  const sensitive = isSensitiveColumn(row.column_name, row.data_type);

  let severity;
  if (sensitive) {
    severity = "critical";
  } else if (!tableLevelGranted) {
    severity = "high"; // column grant bypasses table-level lock
  } else {
    return null; // redundant — table-level access already granted, column-level adds no risk
  }

  if (roles.length === 0) return null;

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
      table_level_select: tableLevelGranted,
      column_level_select: true,
      sensitive,
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
