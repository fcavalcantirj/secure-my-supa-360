// Tests for spec entry 30: HTML report renders the FULL new finding schema.
// The report must be self-contained (no external CDN) so it works offline,
// and must render every finding field: evidence, probe bytes/sample,
// confidence badge, fix SQL + rollback, management/dashboard actions,
// and a suppressed section.

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import { normalizeFinding, assembleResult } from "../scripts/contract.js";
import { renderHtml } from "../scripts/report.js";

/** Build a representative result exercising every finding field type. */
function makeResult() {
  const findings = [
    // Confirmed leak with probe evidence: table with USING(true) + anon read
    normalizeFinding({
      check: "rls_permissive_policy",
      category: "coverage-rls",
      severity: "critical",
      confidence: "confirmed",
      target: "sensitive_photos",
      evidence: { rows_sampled: 3, columns: ["patient_cpf", "url"] },
      probe: {
        status: 200,
        bytes: 512,
        sample: { row_count: 3, columns: ["patient_cpf", "url"] },
      },
      fix: {
        sql: ["ALTER TABLE sensitive_photos ENABLE ROW LEVEL SECURITY;"],
        rollback_sql: ["ALTER TABLE sensitive_photos DISABLE ROW LEVEL SECURITY;"],
        dashboard_action: "Review RLS policy in Table Editor",
        requires_service_role: false,
      },
      references: ["https://supabase.com/docs/guides/auth/row-level-security"],
      title: "RLS permissive policy allows public read",
      explain: "A policy with USING(true) allows any authenticated user to read all rows.",
    }),
    // Inferred finding with management API action: function missing auth check
    normalizeFinding({
      check: "function_secdef_missing_auth_check",
      category: "coverage-rpc",
      severity: "high",
      confidence: "inferred",
      target: "attach_company_admin",
      evidence: { prosecdef: true, body_preview: "EXECUTE 'SELECT * FROM ...'" },
      fix: {
        sql: ["REVOKE ALL ON FUNCTION attach_company_admin(uuid) FROM anon;"],
        rollback_sql: ["GRANT EXECUTE ON FUNCTION attach_company_admin(uuid) TO anon;"],
        management_api_action: {
          method: "PATCH",
          path: "/v1/projects/ref/functions/attach_company_admin",
          body: { verify_jwt: true },
        },
        requires_service_role: false,
      },
      references: ["https://supabase.com/docs/guides/functions"],
      title: "Security definer function missing auth check",
      explain: "Function runs as definer without checking auth.uid().",
    }),
    // Medium finding with dashboard_action + suppressed
    normalizeFinding({
      check: "storage_bucket_public",
      category: "coverage-storage",
      severity: "medium",
      confidence: "inferred",
      target: "bucket:media",
      evidence: { public: true, bucket_id: "media" },
      fix: {
        sql: ["UPDATE storage.buckets SET public = false WHERE id = 'media';"],
        rollback_sql: ["UPDATE storage.buckets SET public = true WHERE id = 'media';"],
        dashboard_action: "Set Private in Storage -> Buckets",
        requires_service_role: false,
      },
      references: [],
      title: "Public storage bucket",
      explain: "Bucket is publicly readable without authentication.",
      suppressed: true,
      suppressed_reason: "Known issue, tracked in JIRA-123",
    }),
  ];

  return assembleResult({
    project_ref: "fixture-ref",
    project_name: "Test Project",
    region: "us-east-1",
    mode: "audit-active",
    rawFindings: findings,
    generated_at: "2026-08-28T12:00:00.000Z",
  });
}

// === Confidence badge ===

test("report: HTML shows confidence badge (confirmed + inferred)", () => {
  const html = renderHtml(makeResult());
  assert.ok(html.includes("CONFIRMED"), "should show CONFIRMED confidence badge");
  assert.ok(html.includes("INFERRED"), "should show INFERRED confidence badge");
});

// === Fix SQL + rollback ===

test("report: HTML renders fix.sql array entries", () => {
  const html = renderHtml(makeResult());
  assert.ok(
    html.includes("ALTER TABLE sensitive_photos ENABLE ROW LEVEL SECURITY"),
    "should render fix.sql[0] — table lock"
  );
  assert.ok(
    html.includes("REVOKE ALL ON FUNCTION attach_company_admin(uuid) FROM anon"),
    "should render fix.sql[0] — function revoke"
  );
});

test("report: HTML renders rollback_sql entries", () => {
  const html = renderHtml(makeResult());
  assert.ok(
    html.includes("ALTER TABLE sensitive_photos DISABLE ROW LEVEL SECURITY"),
    "should render rollback_sql[0] — table"
  );
  assert.ok(
    html.includes("GRANT EXECUTE ON FUNCTION attach_company_admin(uuid) TO anon"),
    "should render rollback_sql[0] — function"
  );
});

test("report: HTML renders all-fix bundle from fix.sql arrays", () => {
  const html = renderHtml(makeResult());
  // The "all fixes" bundle should contain fix SQL from multiple findings
  assert.ok(html.includes("ALTER TABLE sensitive_photos"), "all-fixes should include table fix");
  assert.ok(html.includes("REVOKE ALL ON FUNCTION"), "all-fixes should include function fix");
});

// === Management API + dashboard actions ===

test("report: HTML renders management_api_action method+path+body", () => {
  const html = renderHtml(makeResult());
  assert.ok(html.includes("PATCH"), "should render management_api_action method");
  assert.ok(html.includes("verify_jwt"), "should render management_api_action body key");
});

test("report: HTML renders dashboard_action", () => {
  const html = renderHtml(makeResult());
  assert.ok(html.includes("Review RLS policy in Table Editor"), "should render dashboard_action");
  assert.ok(
    html.includes("Set Private in Storage"),
    "should render dashboard_action for bucket"
  );
});

// === Evidence + probe ===

test("report: HTML renders probe bytes and sample columns", () => {
  const html = renderHtml(makeResult());
  assert.ok(html.includes("512"), "should render probe bytes leaked");
  assert.ok(html.includes("patient_cpf"), "should render probe sample columns");
  assert.ok(html.includes("HTTP 200"), "should render probe HTTP status");
  assert.ok(html.includes("row"), "should render probe row count");
});

test("report: HTML renders evidence object", () => {
  const html = renderHtml(makeResult());
  // evidence.rows_sampled should appear somewhere in the detail/expansion
  assert.ok(html.includes("rows_sampled") || html.includes("Rows sampled"), "should show evidence");
});

// === Suppressed ===

test("report: HTML has a suppressed findings section", () => {
  const html = renderHtml(makeResult());
  const lower = html.toLowerCase();
  assert.ok(
    lower.includes("suppressed"),
    "should have a suppressed findings section heading"
  );
  assert.ok(html.includes("JIRA-123"), "should show suppressed reason");
});

// === Self-contained / offline ===

test("report: HTML is self-contained — no external CDN assets", () => {
  const html = renderHtml(makeResult());
  assert.ok(!html.includes("cdn.tailwindcss.com"), "should not use Tailwind CDN");
  assert.ok(!html.includes("cdn.jsdelivr.net"), "should not use jsDelivr CDN");
  assert.ok(!html.includes("chart.js"), "should not load Chart.js externally");
  assert.ok(html.includes("<!DOCTYPE html>"), "should start with DOCTYPE");
  // All <style> should be inline, not linked
  assert.ok(!html.match(/<link[^>]+stylesheet[^>]+cdn/i), "should not link external stylesheets");
});

// === Full structure ===

test("report: HTML renders severity badges + summary for every finding", () => {
  const html = renderHtml(makeResult());
  const result = makeResult();
  for (const f of result.findings) {
    const sevLabel = f.severity.toUpperCase();
    assert.ok(
      html.includes(sevLabel),
      `should render severity ${sevLabel} for finding ${f.check}`
    );
  }
});

test("report: HTML renders target per finding", () => {
  const html = renderHtml(makeResult());
  assert.ok(html.includes("sensitive_photos"), "should render table target");
  assert.ok(html.includes("attach_company_admin"), "should render function target");
  assert.ok(html.includes("bucket:media"), "should render bucket target");
});

test("report: HTML renders references links", () => {
  const html = renderHtml(makeResult());
  assert.ok(html.includes("supabase.com/docs/guides/auth/row-level-security"), "should render reference URL");
  assert.ok(html.includes("supabase.com/docs/guides/functions"), "should render second reference URL");
});

// === WO-13: incomplete scan banner (failed/timed-out scan must NOT show A+ 100/100) ===

// Load the sanitized failed-scan fixture — mirrors a real run with 8 errors,
// timed_out=true, n_tables_scanned=0, but with project-specific data redacted
// so it works on a fresh clone (fixtures/ is tracked; evidence/ is gitignored).
const failedResult = JSON.parse(
  readFileSync(new URL("../fixtures/failed-scan.json", import.meta.url), "utf8")
);

test("report: failed scan renders INCOMPLETE SCAN banner listing scan_failures", () => {
  const html = renderHtml(failedResult);
  assert.ok(html.includes("INCOMPLETE"), "should show INCOMPLETE banner");
  assert.ok(html.includes("could not run"), "banner should say checks could not run");
  // Every error check name should be listed
  for (const e of failedResult.errors) {
    assert.ok(html.includes(e.check), `should list failed check: ${e.check}`);
  }
});

test("report: failed scan suppresses letter grade and green no-findings box", () => {
  const html = renderHtml(failedResult);
  // No grade "A+" or "Score: 100" — the scan didn't run, no score is valid.
  assert.ok(!html.includes("Score: 100"), "should NOT show Score: 100 on a failed scan");
  assert.ok(!html.includes("No security issues found."), "should NOT show green no-findings box on a failed scan");
});

test("report: failed scan still shows mode + probe banners and coverage", () => {
  const html = renderHtml(failedResult);
  assert.ok(html.includes("Mode:"), "should show mode banner");
  assert.ok(html.includes("Passive scan"), "should show passive banner (no active probe)");
  assert.ok(html.includes("Tables scanned"), "should show coverage section");
  assert.ok(html.includes("did not complete"), "should explain no findings could be produced");
});

test("report: passive run (active_probe.enabled=false) shows passive banner, not 'Active probe ran'", () => {
  const html = renderHtml(failedResult);
  assert.ok(!html.includes("Active probe ran"), "passive scan must not claim probe ran");
});

// === Regression: a successful scan still shows the grade ===

test("report: successful scan shows grade + score (not suppressed)", () => {
  const html = renderHtml(makeResult());
  assert.ok(html.includes("Score:"), "should show score for a successful scan");
  assert.ok(!html.includes("INCOMPLETE SCAN"), "should not show incomplete banner on a healthy result");
  assert.ok(!html.includes("No grade assigned"), "should not show grade-suppression message on a healthy result");
});
