// Realtime authorization auditor (pure, DB-free, unit-testable).
//
// Spec entry 20 (coverage-realtime):
//  - Keep: tables in supabase_realtime publication WITHOUT RLS (critical)
//  - Add: realtime.messages / broadcast / presence authorization policies
//  - Flag broadcast channels readable/writable by anon without policy
//
// Input from audit.js:
//   realtimeTables: [{ table_name, rls_enabled, in_publication }]
//   realtimeMessages: { rls_enabled, anon_select, anon_insert, auth_select,
//                       auth_insert, anon_delete, has_policies } | null
//
// probeFn: async (tableName) -> { status, rowCount, bytes } | null
//   Pass null to skip active probing (confidence stays 'inferred').

/**
 * Classify a table in the supabase_realtime publication.
 * Returns an array of findings (0 or 1). A finding is produced when the table
 * is in the realtime publication but has RLS disabled.
 *
 * @param {object} table — { table_name, rls_enabled, in_publication }
 * @param {object|null} probe — { status, rowCount, bytes } from active anon probe
 * @returns {Array} findings
 */
export function classifyRealtimeTable(table, probe = null) {
  if (!table || !table.in_publication || table.rls_enabled === true) return [];

  const findings = [];
  const confirmed = probe && probe.status === 200 && (probe.rowCount || 0) > 0;

  findings.push({
    check: "realtime_publication_no_rls",
    category: "coverage-realtime",
    severity: "critical",
    confidence: confirmed ? "confirmed" : "inferred",
    target: `table:${table.table_name}`,
    evidence: {
      in_publication: "supabase_realtime",
      rls_enabled: false,
      ...(probe
        ? { probe: { status: probe.status, row_count: probe.rowCount ?? null, bytes: probe.bytes ?? null } }
        : {}),
    },
    fix: {
      sql: [
        `ALTER TABLE ${table.schema_name || "public"}.${table.table_name} ENABLE ROW LEVEL SECURITY;`,
        `-- Or remove from publication: ALTER PUBLICATION supabase_realtime DROP TABLE ${table.schema_name || "public"}.${table.table_name};`,
      ],
      rollback_sql: [
        `ALTER TABLE ${table.schema_name || "public"}.${table.table_name} DISABLE ROW LEVEL SECURITY;`,
      ],
      dashboard_action: null,
      management_api_action: null,
      requires_service_role: false,
    },
  });

  return findings;
}

/**
 * Classify the realtime.messages table (broadcast/presence) for anon access.
 * Flags anon-readable and/or anon-writable channels when RLS is off or no
 * policies exist to gate access.
 *
 * @param {object|null} config — { rls_enabled, anon_select, anon_insert,
 *   auth_select, auth_insert, anon_delete, has_policies }
 * @param {string} [ref="unknown"] — project ref (unused but kept for API symmetry)
 * @returns {Array} findings
 */
export function classifyRealtimeMessages(config, ref = "unknown") {
  if (!config) return [];

  const findings = [];
  const { rls_enabled, anon_select, anon_insert, has_policies } = config;

  // An RLS-enabled table with ZERO policies denies ALL access (RLS blocks
  // everything by default) — so anon grants are currently harmless but likely
  // unintended. Downgrade to defense-in-depth (low) in that case, mirroring
  // the table-level rls_no_policies_with_anon_grants check.
  const rlsOnNoPolicies = rls_enabled && !has_policies;
  const severityFor = (base) => (rlsOnNoPolicies ? "low" : base);
  const reasonFor = (base) => rlsOnNoPolicies
    ? "RLS is ON with zero policies — all anon access is currently denied (safe), but unintended; add caller-scoped policies for the intended access"
    : base;

  // Anon can read broadcast/presence messages
  if ((!rls_enabled || !has_policies) && anon_select) {
    findings.push({
      check: "realtime_broadcast_anon_read",
      category: "coverage-realtime",
      severity: severityFor("high"),
      confidence: "inferred",
      target: "table:realtime.messages",
      evidence: {
        rls_enabled,
        has_policies,
        anon_select,
        reason: reasonFor("Anon can SELECT from realtime.messages — broadcast/presence messages are readable without authentication"),
      },
      fix: {
        sql: [
          `ALTER TABLE realtime.messages ENABLE ROW LEVEL SECURITY;`,
          `-- Add a policy to restrict reads: CREATE POLICY "authenticated read" ON realtime.messages FOR SELECT TO authenticated USING ((select auth.uid()) IS NOT NULL);`,
        ],
        rollback_sql: [
          `ALTER TABLE realtime.messages DISABLE ROW LEVEL SECURITY;`,
        ],
        dashboard_action: null,
        management_api_action: null,
        requires_service_role: false,
      },
    });
  }

  // Anon can send (broadcast) messages
  if ((!rls_enabled || !has_policies) && anon_insert) {
    findings.push({
      check: "realtime_broadcast_anon_write",
      category: "coverage-realtime",
      severity: severityFor("critical"),
      confidence: "inferred",
      target: "table:realtime.messages",
      evidence: {
        rls_enabled,
        has_policies,
        anon_insert,
        reason: reasonFor("Anon can INSERT into realtime.messages — anyone can broadcast messages without authentication"),
      },
      fix: {
        sql: [
          `ALTER TABLE realtime.messages ENABLE ROW LEVEL SECURITY;`,
          `-- Add a policy to restrict writes: CREATE POLICY "authenticated send" ON realtime.messages FOR INSERT TO authenticated WITH CHECK ((select auth.uid()) IS NOT NULL);`,
        ],
        rollback_sql: [
          `ALTER TABLE realtime.messages DISABLE ROW LEVEL SECURITY;`,
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
 * Process all realtime data into findings.
 *
 * @param {object} data — { realtimeTables: [], realtimeMessages: {} | null }
 * @param {string} [ref="unknown"] — project ref
 * @param {Function|null} [probeFn=null] — async (tableName) -> { status, rowCount, bytes }
 * @returns {Array} raw finding objects
 */
export async function processRealtime(data = {}, ref = "unknown", probeFn = null) {
  const findings = [];

  // 1. Tables in supabase_realtime publication without RLS
  for (const t of data.realtimeTables || []) {
    let probe = null;
    if (t.rls_enabled === false && probeFn) {
      const pr = await probeFn(t.table_name);
      probe = pr ? { status: pr.status, rowCount: pr.rowCount ?? 0, bytes: pr.bytes } : null;
    }
    const tableFindings = classifyRealtimeTable(t, probe);
    for (const f of tableFindings) findings.push(f);
  }

  // 2. realtime.messages broadcast/presence authorization
  for (const f of classifyRealtimeMessages(data.realtimeMessages, ref)) {
    findings.push(f);
  }

  return findings;
}
