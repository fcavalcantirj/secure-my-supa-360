// View + materialized-view exposure analyzer (pure, DB-free, unit-testable).
// Mirrors scripts/checks/rls.js + rpc.js + function-body.js: feed in structured
// rows from pg_class/pg_get_viewdef and get findings out — zero live DB needed.
//
// Spec coverage (entry 11):
//  - Enumerate public (and exposed-schema) views/matviews with anon/auth grants.
//  - Flag security_invoker=false views (they run as the owner and bypass base-table
//    RLS — the classic RLS-bypass-via-view leak).
//  - Flag views exposing PII columns reachable by anon.
//  - Active-probe each granted view via /rest/v1/<view> like a table.

import { isSensitiveColumn } from "./pii.js";
// Re-export so existing imports (test/views.test.js) keep working.
export { isSensitiveColumn };

// Classify a single view into findings (array — 0, 1, or 2).
// view = {
//   view_name, matview (bool, default false), security_invoker (bool, default true),
//   anon_select (bool), auth_select (bool), columns: ["col1", "col2", ...]
// }
// probe = { status, rowCount, bytes } | null  (anon-key GET ...?select=*&limit=1)
//   status 200 + rowCount>0  -> CONFIRMED leak
//   status 200 + rowCount==0  -> safe/empty
//   status 401/403/42501      -> blocked (safe)
export function classifyView(view, probe = null) {
  const {
    view_name,
    schema_name = "public",
    matview = false,
    security_invoker = false, // PostgreSQL default: a view without the security_invoker option (PG15+) runs as its OWNER — i.e. SECURITY DEFINER
    anon_select = false,
    auth_select = false,
    columns = [],
  } = view;

  const reachable = anon_select || auth_select;
  if (!reachable) return [];

  const confirmed = !!probe && probe.status === 200 && (probe.rowCount || 0) > 0;
  const sensitiveColumns = (columns || []).filter(isSensitiveColumn);

  const probeEvidence = probe
    ? { status: probe.status, row_count: probe.rowCount ?? null, bytes: probe.bytes ?? null }
    : undefined;

  const findings = [];

  // 1. security_invoker = false: view runs as OWNER, bypassing base-table RLS.
  if (!security_invoker) {
    let severity = "high";
    if (confirmed && sensitiveColumns.length) severity = "critical";
    findings.push({
      check: "view_security_definer_bypass",
      category: "coverage-views",
      severity,
      confidence: confirmed ? "confirmed" : "inferred",
      target: view_name,
      details: {
        matview,
        security_invoker: false,
        reachable_by: [anon_select && "anon", auth_select && "authenticated"].filter(Boolean),
      },
      evidence: {
        security_invoker,
        matview,
        anon_select,
        auth_select,
        sensitive_columns: sensitiveColumns,
        ...(probeEvidence ? { probe: probeEvidence } : {}),
      },
      fix: {
        sql: [
          `-- Recreate as SECURITY INVOKER (PG15+) so the view respects caller rights:`,
          `ALTER VIEW ${schema_name}.${view_name} SET (security_invoker = true);`,
          `-- Or revoke anon access: REVOKE SELECT ON ${schema_name}.${view_name} FROM anon;`,
        ],
        rollback_sql: [
          `-- Rollback: revert to SECURITY DEFINER (restore prior state):`,
          `ALTER VIEW ${schema_name}.${view_name} SET (security_invoker = false);`,
        ],
        requires_service_role: false,
      },
    });
  }

  // 2. PII columns exposed to anon.
  if (anon_select && sensitiveColumns.length > 0) {
    let severity = "critical";
    findings.push({
      check: "view_exposes_pii_to_anon",
      category: "coverage-views",
      severity,
      confidence: confirmed ? "confirmed" : "inferred",
      target: view_name,
      details: { sensitive_columns: sensitiveColumns, security_invoker },
      evidence: {
        sensitive_columns: sensitiveColumns,
        security_invoker,
        ...(probeEvidence ? { probe: probeEvidence } : {}),
      },
      fix: {
        sql: [
          `-- Remove PII from the view or revoke anon access:`,
          `REVOKE SELECT ON ${schema_name}.${view_name} FROM anon;`,
          `-- Or redefine the view without sensitive columns:`,
          `-- CREATE OR REPLACE VIEW ${schema_name}.${view_name} AS SELECT non_pii_cols FROM ...;`,
        ],
        rollback_sql: [
          `GRANT SELECT ON ${schema_name}.${view_name} TO anon;`,
        ],
        requires_service_role: false,
      },
    });
  }

  return findings;
}

// Process every view row: actively probe each reachable view, collect findings.
// views: same shape as classifyView's `view` param.
// probeFn: async (viewName) => { status, rowCount, bytes } | null
//   Pass null to skip probing (-> confidence stays 'inferred').
// returns: flat array of finding objects.
export async function processViews(views, probeFn = null) {
  const findings = [];
  for (const v of views) {
    const reachable = v.anon_select || v.auth_select;
    let probe = null;
    if (reachable && probeFn) {
      const pr = await probeFn(v.view_name);
      probe = pr ? { status: pr.status, rowCount: pr.rowCount ?? 0, bytes: pr.bytes } : null;
    }
    for (const f of classifyView(v, probe)) {
      findings.push(f);
    }
  }
  return findings;
}
