// Data API surface configuration auditor (pure, DB-free, unit-testable).
//
// Spec entry 21 (coverage-data-api):
//  - Report Data API enabled/disabled, "Automatically expose new tables" toggle,
//    exposed schemas/tables/functions counts, extra search path.
//  - Recommend disabling auto-expose and/or Harden-Data-API (custom schema)
//    when the app uses few/no tables via REST.
//  - Emit management_api_action to toggle where the API allows.
//
// Input: config object assembled by audit.js from:
//   - default-privileges query (ownersWithLeak)
//   - pg_settings search_path query (exposedSchemas)
//   - Management API project metadata (api_enabled)
//   - table/function count from existing queries
//
//   config = {
//     auto_expose: boolean,         // "Automatically expose new tables" is ON
//     leaky_owner_roles: string[],  // owner roles with default privs to anon/auth
//     exposed_schemas: string[],    // schemas in PostgREST search_path
//     table_count: number,          // tables visible via REST in exposed schemas
//     function_count: number,       // RPC functions executable by anon/auth
//     rest_enabled: boolean|null,   // Data API / REST API enabled flag (from meta)
//   }

/**
 * Classify Data API configuration for exposure.
 *
 * @param {object} config — see module header
 * @param {string} [ref="unknown"] — project ref
 * @returns {Array} raw finding objects
 */
export function classifyDataApiConfig(config, ref = "unknown") {
  if (!config || typeof config !== "object") return [];

  const findings = [];
  const { auto_expose, data_api_enabled = true, leaky_owner_roles, exposed_schemas, table_count, function_count } = config;

  // --- 1. Auto-expose: new tables automatically exposed via REST API ---
  // WO-10: gate on the Data API actually being ON (db_schema non-empty).
  // auto_expose (ownersWithLeak) just means default privileges are leaky —
  // but if the Data API is OFF, no new tables are auto-exposed to REST.
  if (auto_expose && data_api_enabled && Array.isArray(leaky_owner_roles) && leaky_owner_roles.length > 0) {
    const hasSupabaseAdmin = (leaky_owner_roles || []).includes("supabase_admin");
    const hasPostgres = (leaky_owner_roles || []).includes("postgres");

    const fixes = [];
    if (hasPostgres) {
      fixes.push(
        `ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA public REVOKE SELECT, INSERT, UPDATE, DELETE ON TABLES FROM anon;`,
        `ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA public REVOKE SELECT, INSERT, UPDATE, DELETE ON TABLES FROM authenticated;`,
        `ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA public REVOKE USAGE, SELECT ON SEQUENCES FROM anon;`,
        `ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA public REVOKE USAGE, SELECT ON SEQUENCES FROM authenticated;`,
      );
    }
    if (hasSupabaseAdmin) {
      fixes.push(
        `-- supabase_admin-owned defaults cannot be revoked from postgres role.`,
        `-- Toggle this in: Dashboard -> Project Settings -> Data API -> "Automatically expose new tables" = OFF`
      );
    }

    findings.push({
      check: "data_api_auto_expose_on",
      category: "coverage-data-api",
      severity: "medium",
      confidence: "inferred",
      target: `project:${ref}`,
      evidence: {
        auto_expose: true,
        leaky_owner_roles: leaky_owner_roles || [],
        supabase_admin_default_privs: hasSupabaseAdmin,
        exposed_schemas: exposed_schemas || [],
        exposed_table_count: table_count ?? null,
        exposed_function_count: function_count ?? null,
        reason:
          "New tables created in public schema are automatically exposed via the Supabase REST API (Data API). The 'Automatically expose new tables' toggle is ON (default privileges grant anon/authenticated access).",
      },
      fix: {
        sql: fixes,
        rollback_sql: [
          `-- Restore anon/authenticated default privileges to their prior grant level.`,
          `-- Exact rollback is generated at apply time from captured pg_default_acl state (rollback_sql_exact).`,
          `-- This template fallback is a human guide — do NOT blindly re-run all grants; verify actual prior ACL first.`,
        ],
        dashboard_action:
          "Dashboard -> Project Settings -> Data API: toggle OFF 'Automatically expose new tables'",
        management_api_action: null,
        requires_service_role: false,
      },
    });
  }

  // --- 2. Too many functions exposed via REST ---
  // A large anon-executable RPC surface (96+ granted-but-gated functions) is a
  // risk multiplier: more surface for SQL injection / secdef escalation.
  if (typeof function_count === "number" && function_count >= 20) {
    findings.push({
      check: "data_api_many_functions_exposed",
      category: "coverage-data-api",
      severity: "low",
      confidence: "confirmed",
      target: `project:${ref}`,
      evidence: {
        exposed_function_count: function_count,
        reason: `Project exposes ${function_count} anon/authenticated-executable RPC functions via REST — large attack surface`,
      },
      fix: {
        sql: [],
        rollback_sql: [
          `-- No automated rollback: this is an informational finding about RPC surface.`,
          `-- To restore: re-grant EXECUTE on the revoked functions, or re-enable the Data API if it was disabled.`,
        ],
        dashboard_action: null,
        management_api_action: null,
        requires_service_role: false,
      },
    });
  }

  return findings;
}

/**
 * Process Data API configuration into findings.
 * Thin wrapper around classifyDataApiConfig for audit.js wiring symmetry.
 *
 * @param {object} config — see classifyDataApiConfig
 * @param {string} [ref="unknown"] — project ref
 * @returns {Array} raw finding objects
 */
export function processDataApi(config, ref = "unknown") {
  return classifyDataApiConfig(config, ref);
}
