// WO-5: Unit tests for the shared ACL-state capture and exact-rollback module.
// Exercises parseAclEntries, generateRollbackFromState, captureState (with mock
// dbFn), isDefaultPrivFor, and isExecutableSql — the primitives that power
// the exact-rollback path in remediate.js.

import { test } from "node:test";
import assert from "node:assert/strict";
import {
  isExecutableSql,
  isDefaultPrivFor,
  parseAclEntries,
  generateRollbackFromState,
  captureState,
} from "../scripts/checks/state.js";

// === isExecutableSql ===

test("isExecutableSql: rejects comments, blanks, placeholders", () => {
  assert.equal(isExecutableSql("-- a comment"), false);
  assert.equal(isExecutableSql(""), false);
  assert.equal(isExecutableSql("   "), false);
  assert.equal(isExecutableSql("..."), false);
  assert.equal(isExecutableSql(null), false);
  assert.equal(isExecutableSql(undefined), false);
  assert.equal(isExecutableSql(42), false);
});

test("isExecutableSql: accepts real SQL", () => {
  assert.equal(isExecutableSql("REVOKE SELECT ON storage.objects FROM anon;"), true);
  assert.equal(isExecutableSql("ALTER TABLE foo ENABLE ROW LEVEL SECURITY;"), true);
  assert.equal(isExecutableSql("  GRANT SELECT ON t TO anon;"), true);
});

// === isDefaultPrivFor ===

test("isDefaultPrivFor: recognizes default-privilege checks", () => {
  assert.equal(isDefaultPrivFor("default_privileges_not_revoked"), true);
  assert.equal(isDefaultPrivFor("data_api_auto_expose_on"), true);
  assert.equal(isDefaultPrivFor("rls_disabled"), false);
  assert.equal(isDefaultPrivFor("storage_objects_anon_read"), false);
});

// === parseAclEntries ===

test("parseAclEntries: parses named grantees", () => {
  const acl = "{anon=r/postgres,authenticated=rw/postgres}";
  const entries = parseAclEntries(acl);
  assert.equal(entries.length, 2);
  assert.deepEqual(entries[0], { grantee: "anon", privs: "r", grantor: "postgres" });
  assert.deepEqual(entries[1], { grantee: "authenticated", privs: "rw", grantor: "postgres" });
});

test("parseAclEntries: PUBLIC grantee appears as 'public'", () => {
  // PostgreSQL ACL format: grantee=privs/grantor. PUBLIC is empty grantee: "=r/postgres"
  const acl = "{=r/postgres}";
  const entries = parseAclEntries(acl);
  assert.equal(entries.length, 1);
  assert.equal(entries[0].grantee, "public");
  assert.equal(entries[0].privs, "r");
  assert.equal(entries[0].grantor, "postgres");
});

test("parseAclEntries: handles no grantor", () => {
  const entries = parseAclEntries("{anon=r}");
  assert.equal(entries.length, 1);
  assert.equal(entries[0].grantee, "anon");
  assert.equal(entries[0].grantor, "");
});

test("parseAclEntries: empty and null inputs return []", () => {
  assert.deepEqual(parseAclEntries(null), []);
  assert.deepEqual(parseAclEntries(undefined), []);
  assert.deepEqual(parseAclEntries("{}"), []);
  assert.deepEqual(parseAclEntries(""), []);
  assert.deepEqual(parseAclEntries("  "), []);
});

test("parseAclEntries: parses full privilege set", () => {
  const entries = parseAclEntries("{anon=arwdD/postgres}");
  assert.equal(entries[0].privs, "arwdD");
});

// === generateRollbackFromState ===

test("generateRollbackFromState: table state emits GRANT for grantee-of-interest", () => {
  const state = {
    schema: "storage",
    relname: "objects",
    relacl: "{anon=r/postgres,authenticated=rw/postgres}",
  };
  const stmts = generateRollbackFromState(state, { check: "storage_objects_anon_read" });
  assert.equal(stmts.length, 2);
  assert.ok(stmts.some((s) => s.includes("GRANT SELECT ON storage.objects TO anon;")),
    `expected anon SELECT grant, got: ${JSON.stringify(stmts)}`);
  assert.ok(stmts.some((s) => s.includes("GRANT SELECT, UPDATE ON storage.objects TO authenticated;")),
    `expected authenticated SELECT+UPDATE grant, got: ${JSON.stringify(stmts)}`);
});

test("generateRollbackFromState: table state ignores non-interest grantees", () => {
  const state = {
    schema: "public",
    relname: "leaky_owner",
    relacl: "{supabase_admin=r/postgres,anon=arwdD/postgres}",
  };
  const stmts = generateRollbackFromState(state, { check: "rls_leaky_owner_default_privileges" });
  // Only anon is a grantee of interest; supabase_admin is not.
  // ACL chars "arwdD" → a(INSERT), r(SELECT), w(UPDATE), d(DELETE), D(skip: not data-access)
  // Order follows ACL char order: INSERT, SELECT, UPDATE, DELETE.
  assert.equal(stmts.length, 1);
  assert.ok(stmts[0].includes("GRANT INSERT, SELECT, UPDATE, DELETE ON public.leaky_owner TO anon;"),
    `unexpected rollback SQL: ${stmts[0]}`);
});

test("generateRollbackFromState: table state with no grantee-of-interest yields []", () => {
  const state = {
    schema: "public",
    relname: "safe_table",
    relacl: "{supabase_admin=r/postgres}",
  };
  const stmts = generateRollbackFromState(state, { check: "some_check" });
  assert.deepEqual(stmts, []);
});

test("generateRollbackFromState: default-priv state emits ALTER DEFAULT PRIVILEGES", () => {
  const state = {
    owner_role: "postgres",
    schema_name: "public",
    tables_acl: "{anon=r/postgres,authenticated=rw/postgres}",
    sequences_acl: "{anon=U/postgres}",
  };
  const stmts = generateRollbackFromState(state, { check: "default_privileges_not_revoked" });
  // 3 statements: anon tables (SELECT), authenticated tables (SELECT, UPDATE), anon sequences (USAGE)
  assert.equal(stmts.length, 3);
  assert.ok(stmts.some((s) => /ALTER DEFAULT PRIVILEGES.*GRANT SELECT ON TABLES TO anon/.test(s)));
  assert.ok(stmts.some((s) => /ALTER DEFAULT PRIVILEGES.*GRANT SELECT, UPDATE ON TABLES TO authenticated/.test(s)));
  assert.ok(stmts.some((s) => /ALTER DEFAULT PRIVILEGES.*GRANT USAGE ON SEQUENCES TO anon/.test(s)));
});

test("generateRollbackFromState: default-priv with no grantee-of-interest yields []", () => {
  const state = {
    owner_role: "postgres",
    schema_name: "public",
    tables_acl: "{supabase_admin=r/postgres}",
  };
  const stmts = generateRollbackFromState(state, { check: "default_privileges_not_revoked" });
  assert.deepEqual(stmts, []);
});

test("generateRollbackFromState: null state yields []", () => {
  assert.deepEqual(generateRollbackFromState(null, { check: "x" }), []);
  assert.deepEqual(generateRollbackFromState(undefined, { check: "x" }), []);
});

test("generateRollbackFromState: data_api state captures both tables and sequences", () => {
  const state = {
    owner_role: "postgres",
    schema_name: "public",
    tables_acl: "{anon=r/postgres}",
    sequences_acl: "{anon=U/postgres}",
  };
  const stmts = generateRollbackFromState(state, { check: "data_api_auto_expose_on" });
  assert.equal(stmts.length, 2);
  assert.ok(stmts.some((s) => /GRANT SELECT ON TABLES TO anon/.test(s)));
  assert.ok(stmts.some((s) => /GRANT USAGE ON SEQUENCES TO anon/.test(s)));
});

// === captureState ===

test("captureState: returns null when no dbFn provided", async () => {
  const finding = {
    check: "storage_objects_anon_read",
    target: "bucket:media",
    fix: { sql: ["REVOKE SELECT ON storage.objects FROM anon;"] },
  };
  const state = await captureState("token", "ref", finding);
  assert.equal(state, null);
});

test("captureState: returns null for non-SQL fixes", async () => {
  const finding = {
    check: "edge_function_verify_jwt_disabled",
    target: "function:abc123",
    fix: {
      sql: ["-- Only a dashboard action, no SQL fix."],
      dashboard_action: "Dashboard -> ...",
    },
  };
  const dbFn = async () => [];
  const state = await captureState("token", "ref", finding, dbFn);
  assert.equal(state, null);
});

test("captureState: returns null for RLS-only SQL (no ACL operation)", async () => {
  const finding = {
    check: "rls_disabled",
    target: "leaky_table",
    fix: { sql: ["ALTER TABLE public.leaky_table ENABLE ROW LEVEL SECURITY;"] },
  };
  let called = false;
  const dbFn = async () => { called = true; return []; };
  const state = await captureState("token", "ref", finding, dbFn);
  assert.equal(state, null);
  assert.equal(called, false, "must NOT query DB for RLS-only fixes");
});

test("captureState: captures table relacl for REVOKE-based table finding", async () => {
  const finding = {
    check: "rls_leaky_owner_default_privileges",
    target: "table:leaky_owner",
    fix: { sql: ["REVOKE SELECT ON TABLE public.leaky_owner FROM anon;"] },
  };
  const mockState = { schema: "public", relname: "leaky_owner", relacl: "{anon=r/postgres}", rls: true, policies: [] };
  const dbFn = async (query) => {
    assert.ok(query.includes("pg_class"), "should query pg_class for table state");
    assert.ok(query.includes("leaky_owner"), "should filter on the table name");
    return [{ state: mockState }];
  };
  const state = await captureState("token", "ref", finding, dbFn);
  assert.deepEqual(state, mockState);
});

test("captureState: returns null when query returns no rows", async () => {
  const finding = {
    check: "storage_objects_anon_read",
    target: "bucket:media",
    fix: { sql: ["REVOKE SELECT ON storage.objects FROM anon;"] },
  };
  const dbFn = async () => [];
  const state = await captureState("token", "ref", finding, dbFn);
  assert.equal(state, null);
});

test("captureState: captures default-priv state for data_api_auto_expose_on", async () => {
  const finding = {
    check: "data_api_auto_expose_on",
    target: "project:myref",
    evidence: { obj_type: "r" },
    fix: {
      sql: ["ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA public REVOKE SELECT ON TABLES FROM anon;"],
    },
  };
  let queryCount = 0;
  const dbFn = async (query) => {
    queryCount++;
    assert.ok(query.includes("pg_default_acl"), "should query pg_default_acl");
    return [{ owner_role: "postgres", defaclobjtype: "r", acl: "{anon=r/postgres}", schema_name: "public" }];
  };
  const state = await captureState("token", "ref", finding, dbFn);
  assert.ok(state, "should capture state");
  assert.equal(state.tables_acl, "{anon=r/postgres}");
  assert.equal(state.owner_role, "postgres");
  assert.equal(state.schema_name, "public");
  // data_api captures both TABLES ('r') and SEQUENCES ('S')
  assert.equal(queryCount, 2, "should query both table and sequence default ACLs");
});

test("captureState: captures default-priv state for default_privileges_not_revoked", async () => {
  const finding = {
    check: "default_privileges_not_revoked",
    target: "schema:public (owner=postgres, TABLES)",
    evidence: { obj_type: "r" },
    fix: {
      sql: ["ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA public REVOKE SELECT ON TABLES FROM anon;"],
    },
  };
  let queryCount = 0;
  const dbFn = async (query) => {
    queryCount++;
    return [{ owner_role: "postgres", defaclobjtype: "r", acl: "{anon=r/postgres}", schema_name: "public" }];
  };
  const state = await captureState("token", "ref", finding, dbFn);
  assert.ok(state);
  assert.equal(queryCount, 1, "single obj_type for default_privileges_not_revoked");
  assert.equal(state.tables_acl, "{anon=r/postgres}");
});

test("captureState: returns null if dbFn throws", async () => {
  const finding = {
    check: "rls_leaky_owner_default_privileges",
    target: "table:leaky_owner",
    fix: { sql: ["REVOKE SELECT ON TABLE public.leaky_owner FROM anon;"] },
  };
  const dbFn = async () => { throw new Error("connection refused"); };
  const state = await captureState("token", "ref", finding, dbFn);
  assert.equal(state, null);
});

test("captureState: storage bucket with storage.objects fix captures table relacl", async () => {
  const finding = {
    check: "storage_objects_anon_read",
    target: "bucket:media",
    fix: { sql: ["REVOKE SELECT ON storage.objects FROM anon;"] },
  };
  const mockState = { schema: "storage", relname: "objects", relacl: "{anon=r/postgres}", rls: false, policies: [] };
  const dbFn = async () => [{ state: mockState }];
  const state = await captureState("token", "ref", finding, dbFn);
  assert.deepEqual(state, mockState);
});

test("generateRollbackFromState round-trip: capture → revert matches template only when role held the privs", () => {
  // The key WO-5 invariant: if the role held only SELECT, the rollback must grant
  // only SELECT — never INSERT/UPDATE/DELETE.
  const state = {
    schema: "storage",
    relname: "objects",
    relacl: "{anon=r/postgres}", // anon had SELECT only
  };
  const stmts = generateRollbackFromState(state, { check: "storage_objects_anon_read" });
  assert.equal(stmts.length, 1);
  // Must NOT contain INSERT, UPDATE, or DELETE — only SELECT.
  assert.ok(!/INSERT|UPDATE|DELETE/.test(stmts[0]),
    `rollback must not grant write privs the role never had: ${stmts[0]}`);
  assert.ok(/GRANT SELECT/.test(stmts[0]),
    `rollback must restore the exact prior privilege: ${stmts[0]}`);
});
