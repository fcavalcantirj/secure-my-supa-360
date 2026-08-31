// Default-privileges audit (spec entry 22 — coverage-rls).
//
// Flags future objects (TABLES, SEQUENCES, FUNCTIONS) whose pg_default_acl
// still grants privileges to anon/authenticated under a role whose defaults
// were never revoked — the "every new table auto-exposed to the internet"
// hole. This is the class the original tool never checked at all.
//
// PURE module (no DB, no network): it consumes the pg_default_acl rows that
// audit.js fetches and classifies them into findings, exactly like
// scripts/checks/rls.js :: classifyTable / processTables. The SQL query that
// populates those rows lives in audit.js (entry 1 wiring).

// pg_default_acl.defaclobjtype -> human label (spec: TABLES, SEQUENCES, FUNCTIONS).
// ('r' = relations/tables, 'S' = sequences, 'f' = functions; 'T' = types, not audited)
const OBJ_TYPE = {
  r: "TABLES",
  S: "SEQUENCES",
  f: "FUNCTIONS",
};

// Object types we audit, in order.
const OBJ_TYPES = ["r", "S", "f"];

// Owner roles whose default-privilege template we inspect (spec step 1).
// postgres is SQL-revokeable; supabase_admin is NOT (postgres is not a member).
const OWNER_ROLES = ["postgres", "supabase_admin"];
const ADMIN_OWNED = "supabase_admin";

// Grantee roles whose defaults must NOT include anon/authenticated.
const GRANTEE_ROLES = ["anon", "authenticated"];

// WO-8: PostgreSQL "PUBLIC" pseudo-role appears in ACL strings as an empty
// grantee (`=r/owner`), meaning EVERY role (including anon) has the privilege.
// We detect it the same way as an anon grant.
const PUBLIC_GRANTEE = "public";

// Data/EXECUTE privilege letters per object type (documented for reviewers).
const LEAK_PRIVS = {
  r: "a r w d (INSERT/SELECT/UPDATE/DELETE on tables)",
  S: "U S (USAGE/SELECT on sequences)",
  f: "X (EXECUTE on functions)",
};

/** Extract the privilege string granted to `grantee` in an aclid like
 *  `{$_=arwdD/public,anon=arwdD,authenticated=rw}`.
 *  Returns "" when the grantee has no entry (no grant = safe for that grantee).
 */
function grantsToAcl(acl, grantee) {
  if (!acl || !grantee) return "";
  const m = acl.match(new RegExp(grantee + "=([a-zA-Z]+)"));
  return m ? m[1] : "";
}

/** Which of anon/authenticated/PUBLIC (if any) have a grant in this acl?
 *  WO-8: PUBLIC pseudo-role appears as `=privs/owner` (empty grantee in the
 *  ACL string) — meaning EVERY role including anon has the privilege. */
export function aclLeakGrantees(acl) {
  if (!acl) return [];
  const leaks = GRANTEE_ROLES.filter((g) => grantsToAcl(acl, g));
  // PUBLIC grant: empty grantee before = (pattern: `{=X` or `, =X` in the ACL string).
  // Remove all named entries (name=privs) then check for leftover `=privs`.
  const withoutNamed = acl.replace(/[a-zA-Z_]+=([a-zA-Z]+)/g, "");
  if (/=[a-zA-Z]/.test(withoutNamed)) {
    leaks.push(PUBLIC_GRANTEE);
  }
  return leaks;
}

// Extract privilege characters for the PUBLIC pseudo-role from an ACL string.
// PUBLIC appears as `=privs/grantor` (empty grantee before `=`).
function publicAclPrivs(acl, type) {
  if (!acl) return "";
  const m = acl.match(/(?:[{,]|^)\s*=([a-zA-Z]+)/);
  if (!m) return "";
  return aclPrivsToSql(type, m[1]);
}

// Privilege letters that constitute actual data access (data-in / data-out),
// per object type. Privileges like MAINTAIN (m), TRIGGER (t), TRUNCATE (D),
// and REFERENCES (x) are NOT data access — they allow schema operations,
// not row-level reads/writes. A supabase_admin row granting only `m` is inert.
const DATA_ACCESS_PRIVS = {
  r: ["a", "r", "w", "d"],  // INSERT, SELECT, UPDATE, DELETE
  S: ["U", "r", "w", "a"],  // USAGE, SELECT, UPDATE, INSERT
  f: ["X"],                 // EXECUTE
};

/** Check if a grantee has any data-access privilege in the ACL. */
function hasDataPrivs(acl, grantee, type) {
  const aclChars = grantsToAcl(acl, grantee);
  if (!aclChars) return false;
  const dataPrivs = DATA_ACCESS_PRIVS[type] || [];
  return [...aclChars].some((c) => dataPrivs.includes(c));
}

/** Check PUBLIC pseudo-role for data-access privileges. */
function hasPublicDataPrivs(acl, type) {
  if (!acl) return false;
  const m = acl.match(/(?:[{,]|^)\s*=([a-zA-Z]+)/);
  if (!m) return false;
  const dataPrivs = DATA_ACCESS_PRIVS[type] || [];
  return [...m[1]].some((c) => dataPrivs.includes(c));
}

/** Whether any grantee (anon, authenticated, PUBLIC) has data-access privileges. */
function hasDataLeak(acl, type) {
  const grantees = GRANTEE_ROLES.filter((g) => hasDataPrivs(acl, g, type));
  const publicLeak = hasPublicDataPrivs(acl, type);
  return grantees.length > 0 || publicLeak;
}

// Privilege letters -> SQL privilege names, per object type.
// Used to convert captured ACL strings into exact REVOKE/GRANT statements
// so rollback restores the ORIGINAL privileges, not a hardcoded superset
// (WO-5: inverse-of-fix rollback was a privilege escalation on a production project).
const PRIV_MAP = {
  r: { r: "SELECT", a: "INSERT", w: "UPDATE", d: "DELETE", x: "REFERENCES", t: "TRIGGER", D: "TRUNCATE", m: "MAINTAIN" },
  S: { U: "USAGE", r: "SELECT", w: "UPDATE", a: "INSERT" },
  f: { X: "EXECUTE" },
};

// Convert ACL privilege letters (e.g. "rwU") to SQL privilege names
// (e.g. "SELECT, UPDATE, USAGE") for a given object type.
function aclPrivsToSql(type, aclChars) {
  const map = PRIV_MAP[type] || {};
  const privs = [];
  for (const ch of aclChars) {
    if (map[ch] && !privs.includes(map[ch])) privs.push(map[ch]);
  }
  return privs.join(", ");
}

/** SQL fix + rollback for an owner we CAN alter (i.e. not supabase_admin).
 *  Uses the CAPTURED acl to determine exact privileges — REVOKEs only what
 *  was granted, and GRANTs back the EXACT same set on rollback (faithful
 *  restore, not a hardcoded inverse). This prevents the rollback from
 *  escalating privileges (WO-5). */
function sqlFixFor(owner, type, acl, schemaName = "public") {
  const objType = type === "r" ? "TABLES" : type === "S" ? "SEQUENCES" : "FUNCTIONS";
  const stmts = [];
  const rollback = [];
  // WO-10: only revoke DATA-ACCESS privileges (a/r/w/d for tables, U/r/w/a for
  // sequences, X for functions). Non-data privileges like MAINTAIN (m),
  // TRIGGER (t), TRUNCATE (D), REFERENCES (x) are not data access — don't touch them.
  const dataPrivs = DATA_ACCESS_PRIVS[type] || [];
  for (const g of GRANTEE_ROLES) {
    const aclChars = grantsToAcl(acl, g);
    if (!aclChars) continue;
    // Filter to data-access privilege letters only.
    const dataAclChars = [...aclChars].filter((c) => dataPrivs.includes(c)).join("");
    if (!dataAclChars) continue;
    const privs = aclPrivsToSql(type, dataAclChars);
    if (!privs) continue;
    stmts.push(`ALTER DEFAULT PRIVILEGES FOR ROLE ${owner} IN SCHEMA ${schemaName} REVOKE ${privs} ON ${objType} FROM ${g};`);
    rollback.push(`ALTER DEFAULT PRIVILEGES FOR ROLE ${owner} IN SCHEMA ${schemaName} GRANT ${privs} ON ${objType} TO ${g};`);
  }
  // WO-8 + WO-10: PUBLIC grant — only data-access privileges.
  if (acl) {
    const m = acl.match(/(?:[{,]|^)\s*=([a-zA-Z]+)/);
    if (m) {
      const publicDataChars = [...m[1]].filter((c) => dataPrivs.includes(c)).join("");
      if (publicDataChars) {
        const publicPrivs = aclPrivsToSql(type, publicDataChars);
        if (publicPrivs) {
          stmts.push(`ALTER DEFAULT PRIVILEGES FOR ROLE ${owner} IN SCHEMA ${schemaName} REVOKE ${publicPrivs} ON ${objType} FROM PUBLIC;`);
          rollback.push(`ALTER DEFAULT PRIVILEGES FOR ROLE ${owner} IN SCHEMA ${schemaName} GRANT ${publicPrivs} ON ${objType} TO PUBLIC;`);
        }
      }
    }
  }
  return {
    sql: stmts.length ? stmts : [`-- No data-access privileges to revoke on ${objType} for role ${owner}`],
    rollback_sql: rollback,
    dashboard_action: null,
  };
}

/** Fix plan for a supabase_admin-owned leak: NOT SQL-revokeable from postgres. */
function dashboardFix(owner) {
  return {
    sql: [],
    rollback_sql: [],
    dashboard_action:
      "Supabase Dashboard -> Project Settings -> Data API -> toggle " +
      "'Automatically expose new tables' OFF. Default privileges owned by " +
      owner + " (objects created via the Dashboard) cannot be REVOKEd from the " +
      "postgres role, so the dashboard toggle is the only SQL-side control.",
  };
}

/**
 * Classify one pg_default_acl row into a finding (or null when safe).
 *
 * row = { owner_role, defaclobjtype, acl }  (from the audit.js pg_default_acl query,
 *   restricted to owner_role IN (postgres, supabase_admin) and defaclobjtype IN (r,S,f)).
 */
/**
 * Classify one pg_default_acl row into a finding (or null when safe).
 *
 * row = { owner_role, defaclobjtype, acl }
 * creatingRoles = set of roles that actually own objects in the scanned schemas
 *   (determines whether the default-acl row is governing or inert)
 *
 * WO-10: Two gates must pass before MEDIUM:
 *   1. The ACL must grant data-access privileges (a/r/w/d for tables, X for fns)
 *   2. The defaclrole must be a role that actually creates objects (governing)
 * A supabase_admin row with data-access privileges but zero owned objects is
 * inert — downgrade to INFO.
 */
export function classifyDefaultAclRow(row, creatingRoles = []) {
  const owner = row.owner_role;
  const type = row.defaclobjtype;
  const label = OBJ_TYPE[type];
  if (!label) return null; // not a type we audit (e.g. 'T' for types)

  const leakedTo = aclLeakGrantees(row.acl);
  if (leakedTo.length === 0) return null; // no anon/authenticated grant -> safe

  // WO-10 gate 1: only flag if the grants include DATA-ACCESS privileges.
  if (!hasDataLeak(row.acl, type)) return null; // only MAINTAIN/TRIGGER/etc. → inert

  // WO-10 gate 2: determine if this role actually creates objects (governing).
  // A pg_default_acl row fires only when defaclrole creates objects. If no
  // objects are owned by this role in the scanned schemas, the row is inert.
  const isGoverning = creatingRoles.length === 0 || creatingRoles.includes(owner);

  const isDashboardOwned = owner === ADMIN_OWNED;
  const schemaName = row.schema_name || "public";
  const fix = isDashboardOwned ? dashboardFix(owner) : sqlFixFor(owner, type, row.acl, schemaName);

  // WO-10: non-governing rows are downgraded to INFO — they describe platform
  // default state, not an active leak on user-owned objects.
  const severity = isGoverning ? "medium" : "info";

  return {
    check: "default_privileges_not_revoked",
    category: "coverage-rls",
    severity,
    confidence: "inferred",
    target: `schema:${schemaName} (owner=${owner}, ${label})`,
    evidence: {
      owner_role: owner,
      obj_type: type,
      obj_type_label: label,
      acl: row.acl || null,
      grantees: leakedTo,
      leak_privs: LEAK_PRIVS[type],
      governing: isGoverning,
      creating_roles: creatingRoles.length > 0 ? creatingRoles : null,
      reason: isGoverning
        ? null
        : `${owner} owns default privileges but does not own objects in the scanned schemas — row is inert (platform-created objects only, no user data).`,
    },
    fix: {
      sql: fix.sql,
      rollback_sql: fix.rollback_sql,
      dashboard_action: fix.dashboard_action,
      management_api_action: null,
      requires_service_role: false,
    },
    details: {
      guidance_match: isGoverning ? "matches" : "n/a",
      guidance_rule: "Default privileges should not grant data-access (SELECT/INSERT/UPDATE/DELETE) to anon/authenticated (supabase.com docs — disable 'Automatically expose new tables')",
    },
  };
}

/**
 * Classify every pg_default_acl row into findings (mirroring rls.js :: processTables).
 * rows: [{ owner_role, defaclobjtype, acl }]. Returns one finding per leaky (owner, type).
 */
export function classifyDefaultAcls(rows, creatingRoles = []) {
  const findings = [];
  for (const r of rows || []) {
    const f = classifyDefaultAclRow(r, creatingRoles);
    if (f) findings.push(f);
  }
  return findings;
}

export { OBJ_TYPE, OWNER_ROLES, OBJ_TYPES };
