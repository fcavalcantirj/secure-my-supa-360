// Shared DB-state capture and exact-rollback generation for ACL-based findings.
//
// This module centralises the captureState primitive that was previously lab-only
// (scripts/lab.js) and promotes it to the user-facing remediate() --apply path.
// The goal (WO-5): rollback SQL must reflect the *actual* prior ACL, not a
// hardcoded template that may grant privileges the role never held.
//
// Public API:
//   - isExecutableSql(line)          — moved here from remediate.js (re-exported)
//   - isDefaultPrivFor(check)        — does this check operate on pg_default_acl?
//   - captureState(token, ref, finding, dbFn) — snapshot the target's ACL before fix
//   - parseAclEntries(aclStr)        — parse PostgreSQL aclitem[] text → [{grantee, privs, grantor}]
//   - generateRollbackFromState(state, finding) — emit exact restoration GRANTs from captured ACL
//
// No circular dependency: remediate.js imports from this module; this module
// does NOT import from remediate.js. Callers pass an injectable dbFn.

// --- Privilege mapping (mirrors scripts/checks/default_privileges.js PRIV_MAP) ---

// PostgreSQL ACL privilege letters per object type.
const PRIV_MAP = {
  r: { r: "SELECT", a: "INSERT", w: "UPDATE", d: "DELETE", x: "REFERENCES", t: "TRIGGER", D: "TRUNCATE", m: "MAINTAIN" },
  S: { U: "USAGE", r: "SELECT", w: "UPDATE", a: "INSERT" },
  f: { X: "EXECUTE" },
};

// Privilege letters that constitute actual data access (not schema maintenance).
const DATA_ACCESS_PRIVS = {
  r: ["a", "r", "w", "d"],  // INSERT, SELECT, UPDATE, DELETE
  S: ["U", "r", "w", "a"],  // USAGE, SELECT, UPDATE, INSERT
  f: ["X"],                 // EXECUTE
};

// Human-readable object-type labels for ALTER DEFAULT PRIVILEGES.
const OBJ_TYPE_LABEL = {
  r: "TABLES",
  S: "SEQUENCES",
  f: "FUNCTIONS",
};

// Grantee roles that, if leaked, we care about restoring on rollback.
const GRANTEE_ROLES = ["anon", "authenticated"];
const PUBLIC_GRANTEE = "public";

/** Checks whether a grantee (as parsed from ACL text) is one we care about
 *  for rollback restoration. Includes PUBLIC (empty grantee in ACL = every role). */
function isGranteeOfInterest(grantee) {
  return GRANTEE_ROLES.includes(grantee) || grantee === PUBLIC_GRANTEE;
}

// --- isExecutableSql (moved from remediate.js, re-exported for backward compat) ---

/**
 * Check if a SQL line is executable (not a comment-only line or placeholder).
 * Skips blank lines, `--`-prefixed comments, and lines with `...` placeholders.
 */
export function isExecutableSql(line) {
  if (!line || typeof line !== "string") return false;
  const trimmed = line.trim();
  if (!trimmed) return false;
  if (trimmed.startsWith("--")) return false;
  if (trimmed.includes("...")) return false;
  return true;
}

// --- isDefaultPrivFor ---

/** Whether a check ID operates on default privileges (captures pg_default_acl).
 *  Both default_privileges_not_revoked and data_api_auto_expose_on emit
 *  ALTER DEFAULT PRIVILEGES ... IN SCHEMA, so both are state-capturable. */
export function isDefaultPrivFor(check) {
  return check === "default_privileges_not_revoked" || check === "data_api_auto_expose_on";
}

// --- ACL parsing ---

/**
 * Parse a PostgreSQL ACL string (aclitem[]::text) into structured entries.
 * Format: `{grantee=privs/grantor,grantee2=privs2/grantor2}`
 * PUBLIC pseudo-role appears as `=privs/grantor` (empty grantee).
 *
 * @param {string|null} aclStr — e.g. "{anon=r/postgres,authenticated=rw/postgres}"
 * @returns {Array<{grantee: string, privs: string, grantor: string}>}
 */
export function parseAclEntries(aclStr) {
  if (!aclStr || typeof aclStr !== "string") return [];
  const trimmed = aclStr.trim();
  if (!trimmed || trimmed === "{}") return [];
  // Strip outer braces
  const inner = trimmed.replace(/^\{/, "").replace(/\}$/, "").trim();
  if (!inner) return [];
  return inner
    .split(",")
    .map((entry) => {
      // grantee=privs/grantor  (grantor optional, grantee may be empty for PUBLIC)
      const m = entry.match(/^([^=]*)=([a-zA-Z]*)(?:\/([^/]+))?$/);
      if (!m) return null;
      return {
        grantee: m[1] || PUBLIC_GRANTEE,
        privs: m[2] || "",
        grantor: m[3] || "",
      };
    })
    .filter(Boolean);
}

/**
 * Convert privilege letters to SQL privilege names for a given object type,
 * filtered to data-access privileges only (a/r/w/d/U/r/w/a/X).
 * @param {string} objType — 'r' (tables), 'S' (sequences), 'f' (functions)
 * @param {string} aclChars — privilege letters e.g. "arwdD"
 * @returns {string} e.g. "SELECT, INSERT, UPDATE, DELETE" (or "" if none)
 */
function aclPrivsToSql(objType, aclChars) {
  const map = PRIV_MAP[objType] || {};
  const dataPrivs = DATA_ACCESS_PRIVS[objType] || [];
  const privs = [];
  for (const ch of aclChars) {
    if (dataPrivs.includes(ch) && map[ch] && !privs.includes(map[ch])) {
      privs.push(map[ch]);
    }
  }
  return privs.join(", ");
}

/**
 * Generate exact restoration GRANT statements from a captured state object.
 * Only grants privileges that were actually present before the fix — never
 * more (WO-5: rollback must not escalate privileges).
 *
 * @param {object} state — what captureState returned (table or default-priv shape)
 * @param {object} finding — the finding object (for check/target context)
 * @returns {string[]} array of executable GRANT / ALTER DEFAULT PRIVILEGES ... GRANT statements
 */
export function generateRollbackFromState(state, finding) {
  if (!state) return [];
  const stmts = [];

  // --- Table state: { schema, relname, relacl, rls, policies } ---
  // Generated for storage.objects findings (target: bucket:).
  if (state.relacl) {
    const tableName = state.schema && state.relname
      ? `${state.schema}.${state.relname}`
      : "storage.objects";
    const entries = parseAclEntries(state.relacl);
    for (const e of entries) {
      if (!isGranteeOfInterest(e.grantee)) continue;
      const privs = aclPrivsToSql("r", e.privs); // table priv letters
      if (privs) {
        stmts.push(`GRANT ${privs} ON ${tableName} TO ${e.grantee};`);
      }
    }
    return stmts;
  }

  // --- Default-privileges state: { owner_role, schema_name, tables_acl, sequences_acl, ... } ---
  // Generated for default_privileges_not_revoked and data_api_auto_expose_on.
  for (const [aclKey, objType] of [["tables_acl", "r"], ["sequences_acl", "S"], ["functions_acl", "f"]]) {
    const acl = state[aclKey];
    if (!acl) continue;
    const label = OBJ_TYPE_LABEL[objType];
    const entries = parseAclEntries(acl);
    for (const e of entries) {
      if (!isGranteeOfInterest(e.grantee)) continue;
      const privs = aclPrivsToSql(objType, e.privs);
      if (privs) {
        stmts.push(
          `ALTER DEFAULT PRIVILEGES FOR ROLE ${state.owner_role || "postgres"} ` +
          `IN SCHEMA ${state.schema_name || "public"} GRANT ${privs} ON ${label} TO ${e.grantee};`
        );
      }
    }
  }

  return stmts;
}

// --- captureState ---

/** Extract the schema-qualified table name from a GRANT/REVOKE on schema.table.
 *  Returns { schema, relname } or null. */
function extractTableName(sqlStr) {
  const m = sqlStr.match(/(?:ON\s+)?((?:[\w-]+)\.)([\w-]+)\b/i);
  if (m) return { schema: m[1], relname: m[2] };
  return null;
}

/** Escape a string for use in a SQL literal (single-quote doubling). */
function sqlLit(s) {
  return String(s).replace(/'/g, "''");
}

/** Build the table relacl capture query. */
function tableStateQuery(schemaName, relName) {
  return `SELECT json_build_object('schema', n.nspname, 'relname', c.relname, 'relacl', c.relacl::text, 'rls', c.relrowsecurity, 'policies', COALESCE((SELECT json_agg(json_build_object('name', p.policyname, 'cmd', p.cmd, 'roles', p.roles, 'qual', p.qual, 'with_check', p.with_check)) FROM pg_policies p WHERE p.schemaname = n.nspname AND p.tablename = c.relname), '[]'::json)) AS state FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = '${sqlLit(schemaName)}' AND c.relname = '${sqlLit(relName)}'`;
}

/** Capture DB state for a finding's target — used to verify rollback exactness and
 *  to generate exact rollback SQL. Best-effort: returns null if state cannot be
 *  captured (non-ACL fix, query failure, or no matching row).
 *
 * @param {string} token — PAT (passed through to dbFn in production)
 * @param {string} ref — project ref
 * @param {object} finding — the finding object (must have .check, .target, .fix)
 * @param {function} dbFn — injectable: (query) => Promise<rows[]>
 * @returns {Promise<object|null>} captured state object, or null if not capturable
 */
export async function captureState(token, ref, finding, dbFn) {
  if (!dbFn) return null;
  const fix = finding.fix || {};
  const hasSql = Array.isArray(fix.sql) && fix.sql.some((s) => isExecutableSql(s));
  if (!hasSql) return null; // non-SQL fixes can't be verified via DB state

  const sqlStr = Array.isArray(fix.sql) ? fix.sql.join(" ") : "";

  // Only capture state for findings whose fix touches ACLs (REVOKE/GRANT/ALTER DEFAULT PRIVILEGES).
  // RLS-only fixes (ENABLE ROW LEVEL SECURITY) don't need ACL capture — their rollback
  // (DISABLE ROW LEVEL SECURITY) is the exact inverse regardless of ACL state.
  // This avoids a DB round-trip for non-ACL findings.
  const hasAclOperation = /REVOKE|GRANT|ALTER DEFAULT PRIVILEGES/i.test(sqlStr);
  if (!hasAclOperation) return null;

  const target = finding.target;
  const check = finding.check;

  // Extract schema from fix SQL (handles IN SCHEMA <schema> and schema.table patterns).
  let schemaName = "public";
  const inSchemaMatch = sqlStr.match(/IN SCHEMA\s+(\w+)/i);
  if (inSchemaMatch && inSchemaMatch[1] !== "public") {
    schemaName = inSchemaMatch[1];
  }
  const tableSchemaMatch = sqlStr.match(/(?:TABLE|FUNCTION)\s+(\w+)\.\w+/i);
  if (tableSchemaMatch && tableSchemaMatch[1] !== "public") {
    schemaName = tableSchemaMatch[1];
  }

  try {
    // --- Default privileges: data_api_auto_expose_on, default_privileges_not_revoked ---
    if (isDefaultPrivFor(check)) {
      // data_api operates on both TABLES ('r') and SEQUENCES ('S');
      // default_privileges_not_revoked operates on the single type from evidence.
      const objTypes = check === "data_api_auto_expose_on"
        ? ["r", "S"]
        : [finding.evidence?.obj_type || "r"];

      const state = { tables_acl: null, sequences_acl: null, functions_acl: null };
      let found = false;
      for (const objType of objTypes) {
        const r = await dbFn(
          `SELECT d.defaclrole::regrole::text AS owner_role, ` +
          `d.defaclobjtype AS defaclobjtype, ` +
          `d.defaclacl::text AS acl, ` +
          `n.nspname AS schema_name ` +
          `FROM pg_default_acl d ` +
          `JOIN pg_namespace n ON n.oid = d.defaclnamespace ` +
          `WHERE n.nspname = '${sqlLit(schemaName)}' AND d.defaclobjtype = '${objType}'`
        );
        if (r && r[0]) {
          const key = objType === "r" ? "tables_acl" : objType === "S" ? "sequences_acl" : "functions_acl";
          state[key] = r[0].acl || null;
          if (!state.owner_role) state.owner_role = r[0].owner_role;
          if (!state.schema_name) state.schema_name = r[0].schema_name;
          found = true;
        }
      }
      return found ? state : null;
    }

    // --- Storage objects table (fix SQL operates on storage.objects) ---
    // bucket: targets with storage.objects in the fix SQL → capture table relacl
    // (not the bucket config, which is a different object).
    if (target.startsWith("bucket:") && sqlStr.includes("storage.objects")) {
      const r = await dbFn(tableStateQuery("storage", "objects"));
      return r && r[0] ? r[0].state : null;
    }

    // --- Storage bucket config ---
    if (target.startsWith("bucket:")) {
      const relName = target.split(":")[1];
      const r = await dbFn(
        `SELECT row_to_json(b) AS state FROM (SELECT id, public, file_size_limit, allowed_mime_types FROM storage.buckets WHERE id = '${sqlLit(relName)}') b`
      );
      return r && r[0] ? r[0].state : null;
    }

    // --- Column grant ---
    if (target.startsWith("column:schema:")) {
      const parts = target.split(":");
      schemaName = parts[2];
      const relName = parts[4];
      const r = await dbFn(tableStateQuery(schemaName, relName));
      return r && r[0] ? r[0].state : null;
    }

    // --- config-dependent: custom_schema_exposed has comment-only SQL (already caught
    //  by the hasSql guard above). table: targets with ACL-granting fixes fall through
    //  to the generic table capture below — the "table:" prefix is just a naming convention.
    if (target.startsWith("custom_schema_exposed")) {
      return null;
    }

    // --- Function ---
    const relName = target.startsWith("table:") ? target.slice("table:".length) : target;
    if (check.includes("function_no_search_path") || check.includes("function_secdef_no_search_path")) {
      const r = await dbFn(
        `SELECT row_to_json(p) AS state FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = '${sqlLit(schemaName)}' AND p.proname = '${sqlLit(relName.replace(/'/g, "''"))}'`
      );
      return r && r[0] ? r[0].state : null;
    }

    // --- Generic table / view / materialized view ---
    const r = await dbFn(tableStateQuery(schemaName, relName));
    return r && r[0] ? r[0].state : null;
  } catch {
    return null; // State capture is best-effort
  }
}
