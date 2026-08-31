// RLS table-exposure classifier (pure, DB-free, unit-testable).
//
// Fixes the blind spot in the original audit.js: it only fired on
//   (a) RLS disabled + anon grants, or
//   (b) RLS enabled + ZERO policies + anon grants.
// A table with RLS *enabled* and a permissive `USING (true)` policy + anon
// grants is a full read leak (RLS-ON + single USING(true) policy + anon grants) yet fell through
// both branches and produced NO finding. This module classifies that too, and
// grades every finding by whether an active anon probe CONFIRMED real rows.

const PERMISSIVE_QUALS = new Set(["true", "(true)"]);

// Is a policy expression effectively "allow everyone"?
export function isPermissive(expr) {
  if (expr == null) return false; // NULL qual on a permissive policy = no restriction, handled by caller
  return PERMISSIVE_QUALS.has(String(expr).trim().toLowerCase());
}

// Does a policy scope to the caller (auth.uid / jwt / tenant column / role helper)?
export function hasTenantScope(expr) {
  if (!expr) return false;
  return /auth\.uid\(\)|auth\.jwt\(\)|auth\.role\(\)|current_setting\(|get_my_|is_admin\(|company_id|tenant_id|user_id/i.test(
    String(expr)
  );
}

// probe: { status, rowCount, bytes } | null   (from an anon-key GET ...?select=*&limit=1)
//   status 200 + rowCount>0  -> CONFIRMED leak (rows + bytes actually returned to anon)
//   status 200 + rowCount==0 -> reachable but RLS returns nothing (safe/empty)
//   status 401/403 (42501)   -> blocked (safe)
export function probeConfirmsLeak(probe) {
  return !!probe && probe.status === 200 && (probe.rowCount || 0) > 0;
}

// Classify one table into a finding (or null when safe).
// table = {
//   table_name, rls_enabled, policies: [{cmd, roles, qual, with_check}],
//   anon_select, anon_insert, anon_delete, auth_select,
//   sensitive_columns: []            // optional, from a PII classifier
// }
// probe = active anon probe result for this table (or null when probing disabled)
export function classifyTable(table, probe = null) {
  const {
    table_name,
    schema_name = "public",
    rls_enabled,
    policies = [],
    anon_select = false,
    anon_insert = false,
    anon_update = false,
    anon_delete = false,
    auth_select = false,
    auth_insert = false,
    auth_delete = false,
    auth_update = false,
    sensitive_columns = [],
  } = table;

  const anonReachable = anon_select || anon_insert || anon_delete;
  const confirmed = probeConfirmsLeak(probe);

  const base = (check, severity, extra) => {
    // Sensitive PII that is CONFIRMED-leaked escalates to critical.
    let sev = severity;
    if (confirmed && sensitive_columns.length) sev = "critical";
    return {
      check,
      category: "coverage-rls",
      severity: sev,
      confidence: confirmed ? "confirmed" : "inferred",
      target: table_name,
      evidence: {
        rls_enabled,
        n_policies: policies.length,
        anon_select,
        anon_insert,
        anon_delete,
        auth_select,
        sensitive_columns,
        ...(probe ? { probe: { status: probe.status, row_count: probe.rowCount ?? null, bytes: probe.bytes ?? null } } : {}),
      },
      fix: {
        sql: [`ALTER TABLE ${schema_name}.${table_name} ENABLE ROW LEVEL SECURITY;`],
        rollback_sql: [`ALTER TABLE ${schema_name}.${table_name} DISABLE ROW LEVEL SECURITY;`],
        requires_service_role: false,
      },
      ...extra,
    };
  };

  // 1. RLS OFF + any anon grant -> critical (unchanged semantics, now with confidence).
  if (!rls_enabled && anonReachable) {
    return base("rls_disabled", "critical");
  }

  if (rls_enabled) {
    const readPolicies = policies.filter(
      (p) => p.cmd === "SELECT" || p.cmd === "ALL"
    );

    // 2. RLS ON but a permissive/unscoped read policy reachable by anon/auth -> LEAK.
    //    (the miss: one `ALL USING (true)` policy)
    const permissiveRead = readPolicies.find(
      (p) => isPermissive(p.qual) || (p.qual && !hasTenantScope(p.qual))
    );
    if ((anon_select || auth_select) && permissiveRead) {
      return base("rls_permissive_policy", "high", {
        details: {
          policy: permissiveRead.policyname,
          cmd: permissiveRead.cmd,
          using: permissiveRead.qual,
          reason: isPermissive(permissiveRead.qual)
                ? "policy is USING (true) — every row readable"
                : "policy does not scope to the caller (no auth.uid()/tenant check)",
          guidance_match: "matches",
          guidance_rule: "TO authenticated + (select auth.uid()) wrapped + no joins (supabase.com RLS guide)",
          guidance_sql: `CREATE POLICY ${table_name}_owner_read ON ${schema_name}.${table_name} FOR SELECT TO authenticated USING (user_id = (select auth.uid()))`,
        },
        fix: {
          sql: [
            `-- Replace the permissive policy with a caller-scoped one (best practice: (select auth.uid())):`,
            `-- DROP POLICY ${JSON.stringify(permissiveRead.policyname)} ON ${schema_name}.${table_name};`,
            `-- CREATE POLICY ${table_name}_owner_read ON ${schema_name}.${table_name} FOR SELECT TO authenticated USING (user_id = (select auth.uid()));`,
            ...(anon_select ? [`REVOKE SELECT ON ${schema_name}.${table_name} FROM anon;`] : []),
            ...(auth_select ? [`REVOKE SELECT ON ${schema_name}.${table_name} FROM authenticated;`] : []),
          ],
          rollback_sql: [
            `-- Restore anon SELECT grant (rollback of the REVOKE above):`,
            ...(anon_select ? [`GRANT SELECT ON ${schema_name}.${table_name} TO anon;`] : []),
            ...(auth_select ? [`GRANT SELECT ON ${schema_name}.${table_name} TO authenticated;`] : []),
          ],
          requires_service_role: false,
        },
      });
    }

    // 2b. Write-side: INSERT/UPDATE/ALL policy with permissive/missing/unscoped
    //     WITH CHECK reachable by anon -> anon can insert/tamper arbitrary rows.
    const writePolicies = policies.filter(
      (p) => p.cmd === "INSERT" || p.cmd === "UPDATE" || p.cmd === "ALL"
    );
    const permissiveWrite = writePolicies.find(
      (p) => p.with_check == null || isPermissive(p.with_check) || (p.with_check && !hasTenantScope(p.with_check))
    );
    if (anonReachable && permissiveWrite) {
      return base("rls_permissive_write_policy", "high", {
        details: {
          policy: permissiveWrite.policyname,
          cmd: permissiveWrite.cmd,
          using: permissiveWrite.qual,
          with_check: permissiveWrite.with_check,
          reason: permissiveWrite.with_check == null
                ? "policy has no WITH CHECK guard (writes unconstrained)"
                : isPermissive(permissiveWrite.with_check)
                ? "WITH CHECK is true — any values accepted"
                : "WITH CHECK does not scope to the caller (no auth.uid()/tenant check)",
          guidance_match: "matches",
          guidance_rule: "TO authenticated + (select auth.uid()) wrapped + no joins (supabase.com RLS guide)",
          guidance_sql: `CREATE POLICY ${table_name}_owner_write ON ${schema_name}.${table_name} FOR INSERT TO authenticated WITH CHECK (user_id = (select auth.uid()))`,
        },
        fix: {
          sql: (() => {
            // Derive privileges per grantee from captured state — NEVER use a
            // literal privilege list that might over-grant on rollback.
            const anonPrivs = [
              anon_insert && "INSERT", anon_update && "UPDATE", anon_delete && "DELETE",
            ].filter(Boolean);
            const authPrivs = [
              auth_insert && "INSERT", auth_update && "UPDATE", auth_delete && "DELETE",
            ].filter(Boolean);
            const stmts = [
              `-- Replace the permissive write policy with a caller-scoped WITH CHECK:`,
              `-- DROP POLICY ${JSON.stringify(permissiveWrite.policyname)} ON ${schema_name}.${table_name};`,
              `-- CREATE POLICY ${table_name}_owner_write ON ${schema_name}.${table_name} FOR INSERT TO authenticated WITH CHECK (user_id = (select auth.uid()));`,
            ];
            if (anonPrivs.length) stmts.push(`REVOKE ${anonPrivs.join(", ")} ON ${schema_name}.${table_name} FROM anon;`);
            if (authPrivs.length) stmts.push(`REVOKE ${authPrivs.join(", ")} ON ${schema_name}.${table_name} FROM authenticated;`);
            return stmts;
          })(),
          rollback_sql: (() => {
            const anonPrivs = [
              anon_insert && "INSERT", anon_update && "UPDATE", anon_delete && "DELETE",
            ].filter(Boolean);
            const authPrivs = [
              auth_insert && "INSERT", auth_update && "UPDATE", auth_delete && "DELETE",
            ].filter(Boolean);
            const stmts = [`-- Restore anon/authenticated write grants (rollback of the REVOKE above):`];
            if (anonPrivs.length) stmts.push(`GRANT ${anonPrivs.join(", ")} ON ${schema_name}.${table_name} TO anon;`);
            if (authPrivs.length) stmts.push(`GRANT ${authPrivs.join(", ")} ON ${schema_name}.${table_name} TO authenticated;`);
            return stmts;
          })(),
          requires_service_role: false,
        },
      });
    }

    // 2c. USING vs WITH CHECK divergence on UPDATE/ALL (read scope != write scope).
    //     A scoped read with a differently-scoped write enables write-only tampering.
    const updatePolicies = policies.filter(
      (p) => p.cmd === "UPDATE" || p.cmd === "ALL"
    );
    const diverge = updatePolicies.find(
      (p) => p.qual && p.with_check && String(p.qual).trim() !== String(p.with_check).trim()
    );
    if ((anonReachable || auth_select) && diverge) {
      return base("rls_with_check_divergence", "medium", {
        details: {
          policy: diverge.policyname,
          cmd: diverge.cmd,
          using: diverge.qual,
          with_check: diverge.with_check,
          reason: "USING (row scope) differs from WITH CHECK (value scope) — write scope may exceed read scope, enabling write-only tampering.",
          guidance_match: "matches",
          guidance_rule: "Align WITH CHECK to USING scope so write scope matches read scope (supabase.com RLS guide, rule #3)",
          guidance_sql: `ALTER POLICY ${diverge.policyname} ON ${schema_name}.${table_name} USING (${diverge.qual}) WITH CHECK (${diverge.qual})`,
        },
        fix: {
          sql: [
            `-- Align WITH CHECK to the USING scope so write scope matches read scope:`,
            `ALTER POLICY ${JSON.stringify(diverge.policyname)} ON ${schema_name}.${table_name} USING (${diverge.qual}) WITH CHECK (${diverge.qual});`,
          ],
          rollback_sql: [
            `-- Restore the original divergent WITH CHECK scope (rollback of the ALTER POLICY above):`,
            `ALTER POLICY ${JSON.stringify(diverge.policyname)} ON ${schema_name}.${table_name} USING (${diverge.qual}) WITH CHECK (${diverge.with_check});`,
          ],
          requires_service_role: false,
        },
      });
    }

    // 3. RLS ON, ZERO policies, but direct grants remain -> defense-in-depth (low).
    if (policies.length === 0 && (anon_select || anon_insert || anon_update || anon_delete || auth_select || auth_insert || auth_update || auth_delete)) {
      // WO-5: revoke ONLY the specific privileges that were granted (targeted),
      // and restore exactly those on rollback — never REVOKE ALL / GRANT ALL
      // (which would over-grant privileges the role never had).
      const anonPrivs = [];
      if (anon_select) anonPrivs.push("SELECT");
      if (anon_insert) anonPrivs.push("INSERT");
      if (anon_update) anonPrivs.push("UPDATE");
      if (anon_delete) anonPrivs.push("DELETE");
      const authPrivs = [];
      if (auth_select) authPrivs.push("SELECT");
      if (auth_insert) authPrivs.push("INSERT");
      if (auth_update) authPrivs.push("UPDATE");
      if (auth_delete) authPrivs.push("DELETE");
      const revokeStmts = [];
      const grantStmts = [];
      if (anonPrivs.length) {
        const p = anonPrivs.join(", ");
        revokeStmts.push(`REVOKE ${p} ON ${schema_name}.${table_name} FROM anon;`);
        grantStmts.push(`GRANT ${p} ON ${schema_name}.${table_name} TO anon;`);
      }
      if (authPrivs.length) {
        const p = authPrivs.join(", ");
        revokeStmts.push(`REVOKE ${p} ON ${schema_name}.${table_name} FROM authenticated;`);
        grantStmts.push(`GRANT ${p} ON ${schema_name}.${table_name} TO authenticated;`);
      }
      return base("rls_no_policies_with_anon_grants", "low", {
        fix: {
          sql: revokeStmts.length ? revokeStmts : [`-- No anon/authenticated grants to revoke on ${schema_name}.${table_name}`],
          rollback_sql: grantStmts,
          requires_service_role: false,
        },
      });
    }
  }

  return null; // safe
}

// Probing concurrency: bounded pool to avoid overwhelming the PostgREST API
// on large projects (189+ tables). Spec entry 6 scaling fix.
const PROBE_CONCURRENCY = 8;

// Process every table row into findings via classifyTable(), actively probing
// each anon/auth-reachable table. Pure + unit-testable: inject probeFn so a
// test can stub the live probe with a fake (async) (tableName -> {status, rowCount}).
//
// probeFn must return { status, rowCount, bytes } where rowCount is the number of rows
// and bytes is the response size the anon key actually fetched for that table (0 when blocked).
// Pass null to skip probing entirely (-> confidence stays 'inferred' for any finding).
//
// rows: array of { table_name, rls_enabled, policies:[{policyname,cmd,roles,qual,with_check}],
//                  anon_select, anon_insert, anon_delete, auth_select }
// returns: array of classifyTable findings (same shape classifyTable returns).
export async function processTables(rows, probeFn = null) {
  const findings = [];

  // Phase 1: probe all reachable tables concurrently (bounded pool of PROBE_CONCURRENCY).
  // This prevents serial per-table network round-trips that make large projects time out.
  const probeData = new Array(rows.length).fill(null);
  if (probeFn) {
    const reachable = rows
      .map((t, i) => ({
        t,
        i,
        reachable: t.anon_select || t.anon_insert || t.anon_delete || t.auth_select,
      }))
      .filter((r) => r.reachable);

    for (let ci = 0; ci < reachable.length; ci += PROBE_CONCURRENCY) {
      const chunk = reachable.slice(ci, ci + PROBE_CONCURRENCY);
      await Promise.all(
        chunk.map(async ({ t, i }) => {
          const pr = await probeFn(t.table_name);
          probeData[i] = pr ? { status: pr.status, rowCount: pr.rowCount ?? 0, bytes: pr.bytes } : null;
        })
      );
    }
  }

  // Phase 2: classify all tables (sync after probes resolve).
  for (let i = 0; i < rows.length; i++) {
    const finding = classifyTable(rows[i], probeData[i]);
    if (finding) findings.push(finding);
  }
  return findings;
}
