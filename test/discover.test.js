// Tests for scripts/discover.js — entry 40: rls_query_without_tenant_filter
import { test } from "node:test";
import assert from "node:assert/strict";
import { findMissingTenantFilter } from "../scripts/discover.js";

test("findMissingTenantFilter: .from().select() without .eq() on tenant table -> finding", () => {
  const content = `const { data } = await supabase.from('users').select('*');`;
  const findings = findMissingTenantFilter(content, ["users"]);
  assert.equal(findings.length, 1);
  assert.equal(findings[0].check, "rls_query_without_tenant_filter");
  assert.equal(findings[0].severity, "low");
  assert.ok(findings[0].fix_sql.includes(".eq('tenant_col', tenantId)"));
});

test("findMissingTenantFilter: .from().select().eq() on tenant table -> no finding", () => {
  const content = `const { data } = await supabase.from('users').select('*').eq('user_id', auth.uid());`;
  const findings = findMissingTenantFilter(content, ["users"]);
  assert.equal(findings.length, 0);
});

test("findMissingTenantFilter: .from() on non-tenant table -> no finding", () => {
  const content = `const { data } = await supabase.from('logs').select('*');`;
  const findings = findMissingTenantFilter(content, ["users"]);
  assert.equal(findings.length, 0);
});

test("findMissingTenantFilter: empty/tenantTables -> no findings", () => {
  assert.deepEqual(findMissingTenantFilter(".from('users').select('*')", []), []);
  assert.deepEqual(findMissingTenantFilter(null, ["users"]), []);
  assert.deepEqual(findMissingTenantFilter("", ["users"]), []);
});

test("findMissingTenantFilter: .eq() beyond 500-char window -> still flags (heuristic)", () => {
  // Long chain without .eq — should flag (best-effort heuristic)
  const content = `.from('users').select('*').order('created_at', { ascending: false }).limit(100)`;
  const findings = findMissingTenantFilter(content, ["users"]);
  assert.equal(findings.length, 1);
});

test("findMissingTenantFilter: double-quoted table name", () => {
  const content = `supabase.from("users").select('*')`;
  const findings = findMissingTenantFilter(content, ["users"]);
  assert.equal(findings.length, 1);
  assert.equal(findings[0].target, "users");
});

test("findMissingTenantFilter: multiple tables, only one missing filter", () => {
  const content = `
    supabase.from('users').select('*').eq('id', 1);
    supabase.from('orders').select('*');
  `;
  const findings = findMissingTenantFilter(content, ["users", "orders"]);
  assert.equal(findings.length, 1);
  assert.equal(findings[0].target, "orders");
});
