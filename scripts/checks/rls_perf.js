// RLS performance checks (spec entries 36-40): detect policy patterns that
// cause per-row re-evaluation of auth functions, unindexed predicates,
// correlated subqueries in policies, and public-role policies.
//
// Pure module — no DB access, unit-testable with mock policy rows.
// Entry 36: Flag auth functions called UNWRAPPED in a policy (per-row execution).

import { normalizeRoles } from "./storage.js";

// Auth functions that should be wrapped in (select ...) for per-row caching
// by the Postgres optimizer. Unwrapped calls re-execute on every row,
// defeating the initPlan cache and adding overhead proportional to table size.
const AUTH_CALL_PATTERNS = [
  { name: "auth.uid()", regex: /auth\.uid\(\)/gi },
  { name: "auth.jwt()", regex: /auth\.jwt\(\)/gi },
  { name: "auth.role()", regex: /auth\.role\(\)/gi },
  { name: "current_setting(...)", regex: /current_setting\s*\([^)]*\)/gi },
];

// Wrapped (select auth.xxx()) patterns — safe, do NOT flag.
// These are scalar subselects that Postgres caches as initPlan.
const WRAPPED_REGEXES = [
  /\(select\s+auth\.uid\(\s*\)\s*\)/gi,
  /\(select\s+auth\.jwt\(\s*\)\s*\)/gi,
  /\(select\s+auth\.role\(\s*\)\s*\)/gi,
  /\(select\s+current_setting\s*\([^)]*\)\s*\)/gi,
];

// Scan a policy expression for auth function calls that are NOT already
// wrapped in a scalar subselect (select auth.xxx()). Returns an array of
// { name, matched } for each unwrapped call found.
export function findUnwrappedAuthCalls(expr) {
  if (!expr || typeof expr !== "string") return [];

  // Strip properly wrapped (select auth.xxx()) calls — these are safe.
  let stripped = expr;
  for (const pattern of WRAPPED_REGEXES) {
    stripped = stripped.replace(pattern, "");
  }

  // Any remaining auth function calls are unwrapped (per-row execution).
  const results = [];
  for (const { name, regex } of AUTH_CALL_PATTERNS) {
    const re = new RegExp(regex.source, regex.flags);
    let match;
    while ((match = re.exec(stripped)) !== null) {
      results.push({ name, matched: match[0] });
    }
  }
  return results;
}

// Rewrite an expression by wrapping unwrapped auth function calls in
// (select ...). Already-wrapped calls are preserved as-is.
export function wrapAuthCalls(expr) {
  if (!expr || typeof expr !== "string") return expr;

  // Step 1: protect already-wrapped calls with a null-byte placeholder
  const placeholders = [];
  let working = expr;
  for (const pattern of WRAPPED_REGEXES) {
    working = working.replace(pattern, (match) => {
      const ph = `\x00WRAPPED${placeholders.length}\x00`;
      placeholders.push(match);
      return ph;
    });
  }

  // Step 2: wrap remaining (unwrapped) auth calls in (select ...)
  for (const { regex } of AUTH_CALL_PATTERNS) {
    working = working.replace(regex, (match) => `(select ${match})`);
  }

  // Step 3: restore protected calls
  for (let i = 0; i < placeholders.length; i++) {
    working = working.split(`\x00WRAPPED${i}\x00`).join(placeholders[i]);
  }

  return working;
}

// Classify one policy for unwrapped auth function calls.
// policy = { policyname, cmd, roles, qual, with_check }
// tableName = the table the policy is on (for the target/evidence/fix).
// Returns a finding object or null when the policy is clean.
export function classifyPolicyPerf(policy, tableName, schemaName = "public") {
  if (!policy) return null;

  const issues = [];
  const rewrite = [];
  for (const field of ["qual", "with_check"]) {
    if (policy[field]) {
      const calls = findUnwrappedAuthCalls(policy[field]);
      if (calls.length > 0) {
        issues.push({ field, calls });
        const fixed = wrapAuthCalls(policy[field]);
        if (fixed !== policy[field]) {
          rewrite.push({ field, original: policy[field], fixed });
        }
      }
    }
  }

  if (issues.length === 0) return null;

  const allCalls = issues.flatMap((i) => i.calls);
  const cmd = policy.cmd || "ALL";
  const rolesArr = normalizeRoles(policy.roles);

  return {
    check: "rls_unwrapped_auth_fn",
    category: "rls-performance",
    severity: "medium",
    confidence: "inferred",
    target: `policy:${policy.policyname} on ${tableName}`,
    evidence: {
      table_name: tableName,
      policy_name: policy.policyname,
      cmd,
      roles: policy.roles,
      unwrapped_calls: allCalls,
      qual: policy.qual,
      with_check: policy.with_check,
    },
    fix: {
      sql: rewrite.flatMap((r) => [
        `-- Rewrite ${r.field} to wrap auth calls in scalar subselects (per-row cache):`,
        `--   Original: ${r.field} = ${r.original}`,
        `--   Fixed:    ${r.field} = ${r.fixed}`,
        `DROP POLICY ${JSON.stringify(policy.policyname)} ON ${schemaName}.${tableName};`,
        `CREATE POLICY ${JSON.stringify(policy.policyname)} ON ${schemaName}.${tableName} FOR ${cmd} TO ${rolesArr.join(", ")} USING (${r.fixed}) WITH CHECK (${r.fixed});`,
      ]),
      rollback_sql: [
        `-- Restore original policy expression:`,
        `ALTER POLICY ${JSON.stringify(policy.policyname)} ON ${schemaName}.${tableName} USING (${policy.qual}) WITH CHECK (${policy.with_check});`,
      ],
      requires_service_role: false,
    },
    references: [
      "https://supabase.com/docs/guides/auth/row-level-security",
      "https://wiki.postgresql.org/wiki/Planner_Evil_Comments",
    ],
    details: {
      guidance_match: "matches",
      guidance_rule: "Wrap auth.uid()/auth.jwt()/current_setting() in (select ...) for per-row initPlan caching (supabase.com RLS guide)",
      guidance_sql: rewrite.length > 0
        ? `CREATE POLICY ${JSON.stringify(policy.policyname)} ON ${schemaName}.${tableName} FOR ${cmd} TO ${rolesArr.join(", ")} USING (${rewrite.map(r => r.fixed).join(" AND ")}) WITH CHECK (${rewrite.map(r => r.fixed).join(" AND ")})`
        : null,
    },
  };
}

// --- Entry 37: Unindexed policy columns ---

// Strip subquery content (parenthesized SELECT...FROM... expressions) from a
// policy expression, preserving wrapped auth subselects like (select auth.uid())
// which have no FROM clause. This prevents subquery-internal columns (e.g.
// `SELECT id FROM items`) from being attributed to the outer table — only
// columns in direct equality predicates on the outer table are kept.
// Recursively processes nested parentheses so inner subqueries are stripped
// even when wrapped in outer non-subquery parens.
function stripSubqueries(text) {
  if (!text) return "";
  let result = "";
  let i = 0;
  while (i < text.length) {
    if (text[i] === "(") {
      // Find the matching close paren
      let j = i + 1;
      let depth = 1;
      while (j < text.length && depth > 0) {
        if (text[j] === "(") depth++;
        if (text[j] === ")") depth--;
        j++;
      }
      const inner = text.slice(i + 1, j - 1).trim();
      // Strip subqueries: starts with SELECT + has FROM (but preserve
      // select-only subselects like (select auth.uid()) which have no FROM).
      if (/^SELECT\b/i.test(inner) && /\bFROM\b/i.test(inner)) {
        result += " ";
      } else {
        // Not a subquery — keep the parens but recursively strip inside
        result += "(" + stripSubqueries(text.slice(i + 1, j - 1)) + ")";
      }
      i = j;
    } else {
      result += text[i];
      i++;
    }
  }
  return result;
}

// SQL keywords to exclude from column extraction.
const SQL_KEYWORDS = new Set([
  "AND", "OR", "NOT", "NULL", "TRUE", "FALSE", "SELECT", "FROM", "WHERE",
  "IN", "EXISTS", "LIKE", "IS", "INTO", "USING", "CHECK", "TO", "ALL",
  "ANY", "SOME", "AS", "ON", "BY", "HAVING", "GROUP", "ORDER", "LIMIT",
  "OFFSET", "CASE", "WHEN", "THEN", "ELSE", "END", "JOIN", "INNER", "LEFT",
  "RIGHT", "OUTER", "FULL", "CROSS", "DISTINCT", "UNION", "EXCEPT",
  "INTERSECT", "WITH", "INSERT", "UPDATE", "DELETE", "VALUES", "SET",
  "BETWEEN", "CURRENT", "COALESCE", "NULLIF", "CAST", "ARRAY", "ROW",
  "BOOLEAN", "INTEGER", "NUMERIC", "TEXT", "CHAR", "VARCHAR", "TABLE",
]);

// Extract column-like identifiers from a policy expression.
// Strips string literals, removes all parenthesized content (function calls,
// subqueries), then finds bare identifiers excluding SQL keywords and auth.*
// references. Be conservative: this finds CANDIDATE columns; the caller
// filters to equality predicates against auth values before flagging.
export function extractPolicyColumns(expr) {
  if (!expr || typeof expr !== "string") return [];

  let text = expr;

  // 1. Remove string literals (single-quoted, with '' escape handling)
  text = text.replace(/'(?:[^']|'')*'/g, " ");

  // 2. Remove parenthesized content (function calls, subqueries) by depth
  let depth = 0;
  let stripped = "";
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (ch === "(") {
      depth++;
    } else if (ch === ")") {
      if (depth > 0) depth--;
    } else if (depth === 0) {
      stripped += ch;
    }
  }

  // 3. Find identifiers in stripped text (outside all parens)
  const identifiers = new Set();
  const identPattern = /[a-zA-Z_][a-zA-Z0-9_]*/g;
  let match;
  while ((match = identPattern.exec(stripped)) !== null) {
    const word = match[0];
    // Skip SQL keywords
    if (SQL_KEYWORDS.has(word.toUpperCase())) continue;
    // Skip dotted references (e.g., table.column, auth.uid parts)
    const end = match.index + word.length;
    if (end < stripped.length && stripped[end] === ".") continue;
    if (match.index > 0 && stripped[match.index - 1] === ".") continue;
    identifiers.add(word);
  }

  return [...identifiers];
}

// Classify a policy for unindexed columns referenced in equality predicates
// against auth/wrapped-auth values. Only flags columns that:
// (a) are referenced in the policy expression, AND
// (b) are used in a simple equality predicate against an auth function call, AND
// (c) do NOT have a btree index leading with them.
// indexedColumns: set/array of column names that have btree indexes on this table.
// Returns a finding or null.
export function classifyUnindexedPolicy(policy, tableName, indexedColumns, schemaName = "public") {
  if (!policy) return null;

  // Extract columns from equality predicates against auth values.
  // First strip subquery content (SELECT...FROM... expressions) so that
  // subquery-internal columns (e.g. `id` from `(SELECT id FROM items ...)`)
  // are NOT attributed to the outer table. Wrapped auth subselects like
  // `(select auth.uid())` are preserved (no FROM clause).
  const authCols = new Set();
  for (const field of ["qual", "with_check"]) {
    if (!policy[field]) continue;
    const text = stripSubqueries(String(policy[field]));

    // Column = auth_value OR auth_value = column, where auth_value is either
    // the unwrapped form (auth.uid()) or the wrapped scalar subselect form
    // ((select auth.uid())) or current_setting(...) / get_my_*() variants.
    const authOrSetting = "(?:auth\\.\\w+\\(\\s*\\)|\\(select\\s+auth\\.\\w+\\(\\s*\\)\\s*\\)|current_setting\\s*\\([^)]*\\)|\\(select\\s+current_setting\\s*\\([^)]*\\)\\s*\\)|get_my_\\w+\\(\\s*\\)|\\(select\\s+get_my_\\w+\\(\\s*\\)\\s*\\))";
    const patterns = [
      // Pattern 1: column = auth_fn  (column at start of match)
      new RegExp(`(\\w+)\\s*=\\s*${authOrSetting}`, "gi"),
      // Pattern 2: auth_fn = column  (column at end of match)
      new RegExp(`${authOrSetting}\\s*=\\s*(\\w+)`, "gi"),
    ];
    for (const p of patterns) {
      const re = new RegExp(p.source, p.flags);
      let m;
      while ((m = re.exec(text)) !== null) {
        const col = m[1];
        if (col && !SQL_KEYWORDS.has(col.toUpperCase())) authCols.add(col);
      }
    }
  }

  if (authCols.size === 0) return null;

  // Check which auth-equality columns lack btree indexes
  const idxSet = new Set(indexedColumns || []);
  const unindexed = [...authCols].filter((c) => !idxSet.has(c));

  if (unindexed.length === 0) return null;

  return {
    check: "rls_unindexed_policy_column",
    category: "rls-performance",
    severity: "medium",
    confidence: "inferred",
    target: `policy:${policy.policyname} on ${tableName}`,
    evidence: {
      table_name: tableName,
      policy_name: policy.policyname,
      columns: unindexed,
      qual: policy.qual,
      with_check: policy.with_check,
    },
    fix: {
      sql: unindexed.flatMap((col) => [
        `CREATE INDEX CONCURRENTLY idx_${tableName}_${col} ON ${schemaName}.${tableName} USING btree (${col});`,
      ]),
      rollback_sql: unindexed.map((col) => `DROP INDEX IF EXISTS idx_${tableName}_${col};`),
      requires_service_role: false,
    },
    references: [
      "https://supabase.com/docs/guides/auth/row-level-security",
      "https://wiki.postgresql.org/wiki/Indexing_For_Rooms",
    ],
    details: {
      guidance_match: "matches",
      guidance_rule: "Create a btree index on policy columns used in equality predicates against auth values (supabase.com RLS guide)",
      guidance_sql: `CREATE INDEX CONCURRENTLY idx_${tableName}_${unindexed[0]} ON ${schemaName}.${tableName} USING btree (${unindexed[0]});`,
    },
  };
}

// --- Entry 38: Joins / correlated subqueries in policy body ---

// Detect EXISTS(SELECT ... FROM <other_table>) or correlated
// x IN (select ... from <table> where ... = <this_table>.col) in a policy
// expression. These run row-by-row against varying join data.
export function findJoinInPolicy(expr) {
  if (!expr || typeof expr !== "string") return [];

  const findings = [];
  const text = expr;

  // EXISTS (SELECT ... FROM <table>)
  const existsRe = /\bEXISTS\s*\(\s*SELECT\b/gi;
  let m;
  while ((m = existsRe.exec(text)) !== null) {
    findings.push({ type: "exists", index: m.index });
  }

  // col IN (SELECT ... FROM <table> ... WHERE ... = <ref>)
  const inRe = /\b(\w+)\s+IN\s*\(\s*SELECT\b/gi;
  while ((m = inRe.exec(text)) !== null) {
    findings.push({ type: "in_subquery", column: m[1], index: m.index });
  }

  return findings;
}

// Classify a policy for joins/correlated subqueries.
// Returns a finding or null.
export function classifyJoinInPolicy(policy, tableName) {
  if (!policy) return null;

  const issues = [];
  for (const field of ["qual", "with_check"]) {
    if (policy[field]) {
      const joins = findJoinInPolicy(policy[field]);
      if (joins.length > 0) {
        issues.push({ field, joins });
      }
    }
  }

  if (issues.length === 0) return null;

  const allJoins = issues.flatMap((i) => i.joins);

  return {
    check: "rls_policy_join",
    category: "rls-performance",
    severity: "medium",
    confidence: "inferred",
    target: `policy:${policy.policyname} on ${tableName}`,
    evidence: {
      table_name: tableName,
      policy_name: policy.policyname,
      qual: policy.qual,
      with_check: policy.with_check,
      join_patterns: allJoins,
    },
    fix: {
      sql: [
        "-- Recommend: encapsulate the subquery in a SECURITY DEFINER helper:",
        "--   CREATE OR REPLACE FUNCTION public.has_role(uid uuid) RETURNS bool LANGUAGE sql SECURITY DEFINER AS $$",
        "--     SELECT EXISTS (SELECT 1 FROM team_user WHERE team_user.user_id = uid);",
        "--   $$;",
        "-- Then rewrite the policy to call (select has_role((select auth.uid()))) instead of the correlated EXISTS.",
        "-- OR reverse the join: team_id IN (SELECT team_id FROM team_user WHERE user_id = (select auth.uid()))",
      ],
      rollback_sql: [],
      requires_service_role: false,
    },
    references: [
      "https://supabase.com/docs/guides/auth/row-level-security",
    ],
    details: {
      guidance_match: "diverges",
      guidance_rule: "Supabase guidance: avoid joins in policies. This check diverges — it recommends a SECURITY DEFINER helper function as an alternative, which is valid but not the literal guidance.",
      guidance_sql: null,
    },
  };
}

// --- Entry 39: Public-role policies ---

// Classify a policy for having {public} as its role (no explicit TO scoped to
// authenticated). Perf angle: a public-role policy makes Postgres evaluate the
// policy for anon before rejecting.
export function classifyPublicRolePolicy(policy, tableName, schemaName = "public") {
  if (!policy) return null;
  if (!policy.roles) return null;

  // pg_policies.roles can arrive as a text[] string ("{public}") or a JS array (["public"])
  const roles = normalizeRoles(policy.roles);
  const hasPublic = roles.includes("public");

  if (!hasPublic) return null;

  return {
    check: "rls_policy_public_role",
    category: "rls-performance",
    severity: "low",
    confidence: "inferred",
    target: `policy:${policy.policyname} on ${tableName}`,
    evidence: {
      table_name: tableName,
      policy_name: policy.policyname,
      roles: policy.roles,
    },
    fix: {
      sql: [
        `-- Recreate the policy scoped to authenticated only (add TO authenticated):`,
        `DROP POLICY ${JSON.stringify(policy.policyname)} ON ${schemaName}.${tableName};`,
        `CREATE POLICY ${JSON.stringify(policy.policyname)} ON ${schemaName}.${tableName} FOR ${policy.cmd || "ALL"} TO authenticated USING (${policy.qual || "true"}) WITH CHECK (${policy.with_check || policy.qual || "true"});`,
      ],
      rollback_sql: [
        `-- Restore original policy (with public role):`,
        `DROP POLICY ${JSON.stringify(policy.policyname)} ON ${schemaName}.${tableName};`,
        `CREATE POLICY ${JSON.stringify(policy.policyname)} ON ${schemaName}.${tableName} FOR ${policy.cmd || "ALL"} TO ${roles.join(", ")} USING (${policy.qual || "true"}) WITH CHECK (${policy.with_check || policy.qual || "true"});`,
      ],
      requires_service_role: false,
    },
    references: [
      "https://supabase.com/docs/guides/auth/row-level-security",
    ],
    details: {
      guidance_match: "matches",
      guidance_rule: "Use TO authenticated (not PUBLIC) when defining policies — PUBLIC includes anon (supabase.com RLS guide, rule #2)",
      guidance_sql: `CREATE POLICY ${JSON.stringify(policy.policyname)} ON ${schemaName}.${tableName} FOR ${policy.cmd || "ALL"} TO authenticated USING (${policy.qual || "true"}) WITH CHECK (${policy.with_check || policy.qual || "true"})`,
    },
  };
}

// --- Entry 39: Public-role policies (aggregated per table) ---

// Classify all public-role policies on a table into a SINGLE finding.
// projects that deliberately use roles={public} + internal
// get_my_role() on nearly every policy, emitting one finding per policy creates
// a noise storm (268 findings). Aggregating to one per table keeps it auditable
// without the storm.
export function classifyPublicRoleTable(tableName, publicPolicies, schemaName = "public") {
  if (!publicPolicies || publicPolicies.length === 0) return null;

  const policyNames = publicPolicies.map((p) => p.policyname || p.cmd);

  return {
    check: "rls_policy_public_role",
    category: "rls-performance",
    severity: "low",
    confidence: "inferred",
    target: `table:${tableName}`,
    evidence: {
      table_name: tableName,
      public_role_policies: policyNames,
      policy_count: publicPolicies.length,
      sample_policy: publicPolicies[0] || null,
    },
    fix: {
      sql: [
        `-- These ${publicPolicies.length} policy/policies on ${tableName} use role {public}.`,
        `-- Recreate each with TO authenticated (only re-scope policies that are auth-scoped):`,
        ...publicPolicies.flatMap((p) => [
          `DROP POLICY ${JSON.stringify(p.policyname || "unnamed")} ON ${schemaName}.${tableName};`,
          `CREATE POLICY ${JSON.stringify(p.policyname || "unnamed")} ON ${schemaName}.${tableName} FOR ${p.cmd || "ALL"} TO authenticated USING (${p.qual || "true"}) WITH CHECK (${p.with_check || p.qual || "true"});`,
        ]),
      ],
      rollback_sql: [
        `-- Restore original public-role policies:`,
        ...publicPolicies.flatMap((p) => [
          `DROP POLICY ${JSON.stringify(p.policyname || "unnamed")} ON ${schemaName}.${tableName};`,
          `CREATE POLICY ${JSON.stringify(p.policyname || "unnamed")} ON ${schemaName}.${tableName} FOR ${p.cmd || "ALL"} TO ${normalizeRoles(p.roles).join(", ")} USING (${p.qual || "true"}) WITH CHECK (${p.with_check || p.qual || "true"});`,
        ]),
      ],
      requires_service_role: false,
    },
    references: [
      "https://supabase.com/docs/guides/auth/row-level-security",
    ],
  };
}

// Process all policies across all tables for entries 36-39.
// tables: array of { table_name, policies: [{ policyname, cmd, roles, qual, with_check }] }
// indexInfo: optional Map<tableName, string[]> of btree-indexed columns per table.
// Returns findings array.
export function processRlsPerf(tables, indexInfo) {
  const findings = [];
  for (const t of tables) {
    if (!t.policies) continue;
    const schemaName = t.schema_name || "public";
    const indexedCols = indexInfo ? indexInfo.get(t.table_name) || [] : [];
    const publicPolicies = t.policies.filter((p) => normalizeRoles(p.roles).includes("public"));
    const f39 = classifyPublicRoleTable(t.table_name, publicPolicies, schemaName);
    if (f39) findings.push(f39);

    for (const policy of t.policies) {
      const f36 = classifyPolicyPerf(policy, t.table_name, schemaName);
      if (f36) findings.push(f36);
      const f37 = classifyUnindexedPolicy(policy, t.table_name, indexedCols, schemaName);
      if (f37) findings.push(f37);
      const f38 = classifyJoinInPolicy(policy, t.table_name);
      if (f38) findings.push(f38);
    }
  }
  return findings;
}
