// Unit tests for the default-privileges pure classifier (spec entry 22).
// Mirrors the rls.js test pattern: feed mock pg_default_acl rows, assert findings.
// No live DB required.

import { test } from "node:test";
import assert from "node:assert/strict";
import {
  classifyDefaultAcls,
  classifyDefaultAclRow,
  aclLeakGrantees,
} from "../scripts/checks/default_privileges.js";

const ACL_BOTH = "{$_=arwdD/public,anon=arwdD,authenticated=rw}"; // leak to anon + authenticated
const ACL_SAFE = "{postgres=arwdD/postgres}"; // grant only to postgres -> safe

test("aclLeakGrantees: detects anon + authenticated grants", () => {
  assert.deepEqual(aclLeakGrantees(ACL_BOTH).sort(), ["anon", "authenticated"]);
  assert.deepEqual(aclLeakGrantees("{$_=r/public,authenticated=r}"), ["authenticated"]);
  assert.deepEqual(aclLeakGrantees("{$_=r/public,anon=a}"), ["anon"]);
});

test("aclLeakGrantees: empty/null/safe acl -> no leak", () => {
  assert.equal(aclLeakGrantees(null).length, 0);
  assert.equal(aclLeakGrantees("").length, 0);
  assert.equal(aclLeakGrantees(ACL_SAFE).length, 0);
});

test("classifyDefaultAclRow: safe row (grant only to postgres) -> null", () => {
  assert.equal(
    classifyDefaultAclRow({ owner_role: "postgres", defaclobjtype: "r", acl: ACL_SAFE }),
    null
  );
});

test("classifyDefaultAclRow: postgres-owned TABLES grant -> SQL fix + rollback, NO dashboard_action", () => {
  const f = classifyDefaultAclRow({ owner_role: "postgres", defaclobjtype: "r", acl: ACL_BOTH });
  assert.ok(f, "should flag a postgres TABLES leak");
  assert.equal(f.check, "default_privileges_not_revoked");
  assert.equal(f.category, "coverage-rls");
  assert.equal(f.severity, "medium");
  assert.equal(f.confidence, "inferred");
  assert.equal(f.target, "schema:public (owner=postgres, TABLES)");
  // WO-5 revise: ONE statement PER grantee (anon and authenticated separately)
  assert.equal(f.fix.sql.length, 2, "one REVOKE per grantee");
  assert.ok(f.fix.sql[0].includes("REVOKE"), "fix SQL contains REVOKE");
  assert.ok(f.fix.sql[0].includes("FROM anon"), "first statement targets anon");
  assert.ok(f.fix.sql[1].includes("FROM authenticated"), "second statement targets authenticated");
  // Correct PostgreSQL syntax: ON TABLES (not FOR TABLE)
  assert.ok(f.fix.sql[0].includes("ON TABLES"), "uses ON TABLES (PG17 valid syntax)");
  // WO-5: rollback must use EXACT same privileges (no over-grant)
  assert.ok(f.fix.rollback_sql[0].startsWith("ALTER DEFAULT PRIVILEGES"), "rollback is ALTER DEFAULT PRIVILEGES");
  assert.ok(f.fix.rollback_sql[0].includes("GRANT"), "rollback contains GRANT");
  assert.equal(f.fix.dashboard_action, null);
  assert.equal(f.fix.requires_service_role, false);
});

test("classifyDefaultAclRow: supabase_admin-owned grant -> dashboard_action, empty sql (not a failing SQL)", () => {
  const cases = [
    { type: "r", label: "TABLES", acl: ACL_BOTH },
    { type: "S", label: "SEQUENCES", acl: ACL_BOTH },
    // Functions use EXECUTE (X), not table privs — ACL_BOTH's arwdD has no X.
    { type: "f", label: "FUNCTIONS", acl: "{$_=X/public,anon=X,authenticated=X}" },
  ];
  for (const { type, label, acl } of cases) {
    const f = classifyDefaultAclRow({ owner_role: "supabase_admin", defaclobjtype: type, acl });
    assert.ok(f, `supabase_admin ${type}(${label}) should flag`);
    assert.equal(f.fix.sql.length, 0, `supabase_admin ${label} must have NO sql`);
    assert.ok(f.fix.dashboard_action, `supabase_admin ${label} must emit a dashboard_action`);
    assert.equal(f.fix.requires_service_role, false);
    assert.equal(f.target, `schema:public (owner=supabase_admin, ${label})`);
  }
  // WO-10: supabase_admin with ONLY MAINTAIN (m) is inert — no data access → not flagged
  const inert = classifyDefaultAclRow({ owner_role: "supabase_admin", defaclobjtype: "r", acl: "{anon=m,authenticated=m}" });
  assert.equal(inert, null, "supabase_admin MAINTAIN-only grant is inert → no finding");
});

test("classifyDefaultAclRow: sequences grant -> SEQUENCES finding with exact privileges", () => {
  const f = classifyDefaultAclRow({ owner_role: "postgres", defaclobjtype: "S", acl: "{anon=US,authenticated=U}" });
  assert.ok(f);
  assert.equal(f.target, "schema:public (owner=postgres, SEQUENCES)");
  assert.equal(f.fix.sql.length, 2, "one REVOKE per grantee");
  assert.ok(f.fix.sql[0].includes("REVOKE USAGE"), "revokes only USAGE (exact from ACL for anon)");
  assert.ok(f.fix.sql[0].includes("FROM anon"), "first statement targets anon");
  assert.equal(f.fix.dashboard_action, null);
});

test("classifyDefaultAclRow: functions EXECUTE grant -> FUNCTIONS finding", () => {
  const f = classifyDefaultAclRow({ owner_role: "postgres", defaclobjtype: "f", acl: "{anon=X,authenticated=X}" });
  assert.ok(f);
  assert.equal(f.target, "schema:public (owner=postgres, FUNCTIONS)");
  assert.ok(f.fix.sql[0].includes("REVOKE EXECUTE"), "revokes EXECUTE (exact from ACL)");
});

test("WO-10: supabase_admin row with data-access privs downgraded to INFO when non-governing", () => {
  // supabase_admin has default ACLs with data-access privs (arwdD for anon),
  // but if supabase_admin doesn't own any objects (all owned by postgres),
  // the row is inert — downgrade to INFO, not MEDIUM.
  const f = classifyDefaultAclRow(
    { owner_role: "supabase_admin", defaclobjtype: "r", acl: "{$_=arwdD/public,anon=arwdD,authenticated=rw}" },
    ["postgres"]  // only postgres creates objects — supabase_admin is non-governing
  );
  assert.ok(f, "still flagged, but at INFO");
  assert.equal(f.severity, "info", "non-governing row → INFO (inert, not an active leak)");
  assert.equal(f.evidence.governing, false);
  assert.equal(f.evidence.non_governing, undefined); // evidence.governing is the key field
  assert.ok(f.evidence.reason, "non-governing rows have a reason");
  assert.ok(f.evidence.reason.includes("inert"), "reason mentions inertness");
});

test("WO-10: supabase_admin row is MEDIUM when it IS governing (owns objects)", () => {
  const f = classifyDefaultAclRow(
    { owner_role: "supabase_admin", defaclobjtype: "r", acl: "{$_=arwdD/public,anon=arwdD,authenticated=rw}" },
    ["postgres", "supabase_admin"]  // supabase_admin creates objects → governing
  );
  assert.ok(f);
  assert.equal(f.severity, "medium", "governing row with data-access privs → MEDIUM");
  assert.equal(f.evidence.governing, true);
  assert.equal(f.evidence.reason, null, "governing rows have no reason");
});

test("WO-10: empty creatingRoles → all rows governing (backward compat)", () => {
  const f = classifyDefaultAclRow(
    { owner_role: "supabase_admin", defaclobjtype: "r", acl: "{$_=arwdD/public,anon=arwdD,authenticated=rw}" },
    []  // empty → all rows treated as governing (no info available)
  );
  assert.ok(f);
  assert.equal(f.severity, "medium");
});

test("WO-5 divergent-grantee TABLES: rollback for anon contains ONLY anon's original privileges", () => {
  // Case 1 from architect: anon=arwdDxtm (all table privs), authenticated=arwd (subset)
  const f = classifyDefaultAclRow({ owner_role: "postgres", defaclobjtype: "r", acl: "{postgres=arwdDxtm/postgres, anon=arwdDxtm/postgres, authenticated=arwd/postgres}" });
  assert.ok(f);
  // WO-5 + WO-10: rollback contains ONLY data-access privs (a/r/w/d), NOT MAINTAIN/TRIGGER/etc.
  const anonRollback = f.fix.rollback_sql.find((s) => s.includes("TO anon"));
  assert.ok(anonRollback, "rollback statement for anon exists");
  assert.ok(anonRollback.includes("SELECT"), "anon rollback has SELECT (data-access)");
  assert.ok(anonRollback.includes("INSERT"), "anon rollback has INSERT (data-access)");
  assert.ok(!anonRollback.includes("MAINTAIN"), "anon rollback does NOT include MAINTAIN (non-data-access, WO-10)");
  assert.ok(!anonRollback.includes("REFERENCES"), "anon rollback does NOT include REFERENCES (non-data-access)");
  // authenticated's rollback should NOT have MAINTAIN (they don't have it in ACL)
  const authRollback = f.fix.rollback_sql.find((s) => s.includes("TO authenticated"));
  assert.ok(!authRollback.includes("MAINTAIN"), "authenticated rollback does NOT get MAINTAIN (not in their ACL)");
});

test("WO-5 divergent-grantee SEQUENCES: rollback for anon contains ONLY anon's original privileges", () => {
  // Case 2 from architect: anon=w (UPDATE), authenticated=rwU
  const f = classifyDefaultAclRow({ owner_role: "postgres", defaclobjtype: "S", acl: "{postgres=rwU/postgres, anon=w/postgres, authenticated=rwU/postgres}" });
  assert.ok(f);
  const anonRollback = f.fix.rollback_sql.find((s) => s.includes("TO anon"));
  assert.ok(anonRollback, "anon rollback exists");
  assert.ok(anonRollback.includes("UPDATE"), "anon had UPDATE");
  assert.ok(!anonRollback.includes("USAGE"), "anon does NOT get USAGE (authenticated's priv)");
  assert.ok(!anonRollback.includes("SELECT"), "anon does NOT get SELECT (authenticated's priv)");
});

test("WO-5: rollback REVOKEs exact ACL privileges, never over-grants", () => {
  // SEQUENCES: anon=rw (read+write, NOT USAGE), authenticated=r (read only)
  const f = classifyDefaultAclRow({ owner_role: "postgres", defaclobjtype: "S", acl: "{anon=rw,authenticated=r}" });
  assert.ok(f);
  // Two statements (one per grantee)
  assert.equal(f.fix.sql.length, 2, "one REVOKE per grantee");
  assert.equal(f.fix.rollback_sql.length, 2, "one GRANT per grantee");

  // anon's REVOKE: SELECT, UPDATE (no USAGE)
  const anonRevoke = f.fix.sql.find((s) => s.includes("FROM anon"));
  assert.ok(anonRevoke, "anon REVOKE exists");
  assert.ok(anonRevoke.includes("SELECT"), "revokes SELECT");
  assert.ok(anonRevoke.includes("UPDATE"), "revokes UPDATE");
  assert.ok(!anonRevoke.includes("USAGE"), "does NOT revoke USAGE (anon never had it)");

  // anon's GRANT: same privileges (no escalation)
  const anonGrant = f.fix.rollback_sql.find((s) => s.includes("TO anon"));
  assert.ok(anonGrant, "anon GRANT exists");
  const revokePrivs = anonRevoke.match(/REVOKE\s+(.+?)\s+/)[1].split(", ").sort();
  const grantPrivs = anonGrant.match(/GRANT\s+(.+?)\s+/)[1].split(", ").sort();
  assert.deepEqual(revokePrivs, grantPrivs, "anon rollback restores exact same privileges (no escalation)");

  // authenticated's REVOKE: SELECT only (no UPDATE)
  const authRevoke = f.fix.sql.find((s) => s.includes("FROM authenticated"));
  assert.ok(authRevoke, "authenticated REVOKE exists");
  assert.ok(authRevoke.includes("SELECT"), "revokes SELECT");
  assert.ok(!authRevoke.includes("UPDATE"), "authenticated never had UPDATE");
});

test("classifyDefaultAcls: postgres + supabase_admin leak rows -> two distinct findings", () => {
  const rows = [
    { owner_role: "postgres", defaclobjtype: "r", acl: ACL_BOTH },
    { owner_role: "supabase_admin", defaclobjtype: "r", acl: ACL_BOTH },
  ];
  const fs = classifyDefaultAcls(rows);
  assert.equal(fs.length, 2);
  assert.equal(fs.filter((f) => f.target.includes("owner=postgres")).length, 1);
  assert.equal(fs.filter((f) => f.target.includes("owner=supabase_admin")).length, 1);
  assert.equal(fs.filter((f) => f.fix.dashboard_action).length, 1); // only supabase_admin -> dashboard
});

test("classifyDefaultAcls: mixed safe + leaky rows -> only leaky flagged", () => {
  const rows = [
    { owner_role: "postgres", defaclobjtype: "r", acl: ACL_SAFE }, // safe
    { owner_role: "postgres", defaclobjtype: "S", acl: "" }, // safe
    { owner_role: "postgres", defaclobjtype: "f", acl: "{authenticated=X}" }, // leak
  ];
  const fs = classifyDefaultAcls(rows);
  assert.equal(fs.length, 1);
  assert.equal(fs[0].target, "schema:public (owner=postgres, FUNCTIONS)");
});

test("classifyDefaultAcls: unknown obj type 'T' -> ignored (null), no finding", () => {
  const fs = classifyDefaultAcls([{ owner_role: "postgres", defaclobjtype: "T", acl: ACL_BOTH }]);
  assert.equal(fs.length, 0);
});

// === WO-5: round-trip property test ===
// The rollback must restore the EXACT original privileges per grantee.
// If we REVOKE privs from grantee X, the rollback must GRANT back exactly
// privs from grantee X (not a union with any other grantee's privileges).

test("WO-5 round-trip: rollback privs match fix privs PER GRANTEE (no escalation)", () => {
  // Divergent grantees: anon has 'arwdD' (all), authenticated has 'r' (SELECT only)
  const acl = "{$_=arwdD/public, anon=arwdD/public, authenticated=r/public}";
  const f = classifyDefaultAclRow({ owner_role: "postgres", defaclobjtype: "r", acl });
  assert.ok(f);
  // For each grantee, the REVOKE privs must equal the GRANT privs
  for (const grantee of ["anon", "authenticated"]) {
    const revokeStmt = f.fix.sql.find((s) => s.includes(`FROM ${grantee}`));
    const grantStmt = f.fix.rollback_sql.find((s) => s.includes(`TO ${grantee}`));
    assert.ok(revokeStmt, `REVOKE statement for ${grantee} exists`);
    assert.ok(grantStmt, `GRANT statement for ${grantee} exists`);
    const revokePrivs = revokeStmt.match(/REVOKE\s+(.+?)\s+/)[1].split(", ").sort();
    const grantPrivs = grantStmt.match(/GRANT\s+(.+?)\s+/)[1].split(", ").sort();
    assert.deepEqual(revokePrivs, grantPrivs, `${grantee}: rollback restores exact same privileges as fix revoked`);
  }
  // anon's rollback must NOT contain SELECT (authenticated's priv) beyond its own
  const authGrant = f.fix.rollback_sql.find((s) => s.includes("TO authenticated"));
  const grantPrivs = authGrant.match(/GRANT\s+(.+?)\s+/)[1];
  assert.ok(!grantPrivs.includes("INSERT"), "authenticated rollback does NOT get INSERT (anon's priv, escalation)");
});

test("aclLeakGrantees: PUBLIC grant (empty grantee) is detected", () => {
  // WO-8: {=r/public} means PUBLIC (empty grantee) has SELECT — every role including anon.
  assert.ok(aclLeakGrantees("{$_=arwdD/public, =r/public}").includes("public"));
  assert.ok(aclLeakGrantees("{=r/public}").includes("public"));
  // No PUBLIC grant -> no public in leaks
  assert.ok(!aclLeakGrantees("{$_=arwdD/public,anon=arwdD/public}").includes("public"));
});

test("WO-5 round-trip: SEQUENCES divergent grantee — anon w, auth rwU", () => {
  // Case 2 from architect: anon=w (UPDATE), authenticated=rwU (SELECT, UPDATE, USAGE)
  const f = classifyDefaultAclRow({ owner_role: "postgres", defaclobjtype: "S", acl: "{postgres=rwU/postgres, anon=w/postgres, authenticated=rwU/postgres}" });
  assert.ok(f);
  // anon rollback: only UPDATE (never USAGE or SELECT)
  const anonGrant = f.fix.rollback_sql.find((s) => s.includes("TO anon"));
  assert.ok(anonGrant, "anon GRANT exists");
  const anonMatch = anonGrant.match(/GRANT\s+(.+?)\s+ON/);
  assert.ok(anonMatch, "GRANT pattern matches");
  const anonPrivs = anonMatch[1];
  assert.ok(anonPrivs.includes("UPDATE"), "anon had UPDATE");
  assert.ok(!anonPrivs.includes("USAGE"), "anon NEVER gets USAGE (would be escalation)");
  assert.ok(!/\bSELECT\b/.test(anonPrivs), "anon NEVER gets SELECT (would be escalation)");
  // authenticated rollback: USAGE + SELECT + UPDATE
  const authGrant = f.fix.rollback_sql.find((s) => s.includes("TO authenticated"));
  const authMatch = authGrant.match(/GRANT\s+(.+?)\s+ON/);
  assert.ok(authMatch, "auth GRANT pattern matches");
  const authPrivs = authMatch[1];
  assert.ok(authPrivs.includes("USAGE"), "authenticated had USAGE");
});
