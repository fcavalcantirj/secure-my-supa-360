import { test } from "node:test";
import assert from "node:assert/strict";
import {
  classifyView,
  processViews,
  isSensitiveColumn,
} from "../scripts/checks/views.js";

test("isSensitiveColumn detects PII column names", () => {
  assert.equal(isSensitiveColumn("email"), true);
  assert.equal(isSensitiveColumn("user_cpf"), true);
  assert.equal(isSensitiveColumn("patient_phone"), true);
  assert.equal(isSensitiveColumn("id"), false);
  assert.equal(isSensitiveColumn("name"), false);
  assert.equal(isSensitiveColumn("created_at"), false);
  assert.equal(isSensitiveColumn("birthdate"), true);
  assert.equal(isSensitiveColumn(null), false);
});

test("security-definer view + anon read + probe confirms -> view_security_definer_bypass (high, confirmed)", () => {
  const view = {
    view_name: "user_profiles_v",
    matview: false,
    security_invoker: false,
    anon_select: true,
    auth_select: false,
    columns: ["id", "name"],
  };
  const findings = classifyView(view, { status: 200, rowCount: 3, bytes: 256 });
  const bypass = findings.find((f) => f.check === "view_security_definer_bypass");
  assert.ok(bypass, `expected bypass finding, got: ${findings.map((f) => f.check).join(", ")}`);
  assert.equal(bypass.confidence, "confirmed");
  assert.equal(bypass.severity, "high");
  assert.equal(bypass.evidence.probe.status, 200);
  assert.equal(bypass.evidence.probe.row_count, 3);
  assert.equal(bypass.evidence.probe.bytes, 256);
});

test("security-definer view + PII + probe confirms -> escalated to critical", () => {
  const view = {
    view_name: "patient_v",
    security_invoker: false,
    anon_select: true,
    columns: ["id", "name", "email"],
  };
  const findings = classifyView(view, { status: 200, rowCount: 1, bytes: 128 });
  // Both bypass + PII exposure fire; bypass escalates to critical (PII + confirmed)
  const bypass = findings.find((f) => f.check === "view_security_definer_bypass");
  assert.ok(bypass);
  assert.equal(bypass.severity, "critical");
});

test("security_invoker=true -> no findings (safe, even with anon grants)", () => {
  const view = {
    view_name: "safe_view",
    security_invoker: true,
    anon_select: true,
    columns: ["id"],
  };
  assert.equal(classifyView(view, { status: 200, rowCount: 0 }).length, 0);
  assert.equal(classifyView(view, null).length, 0);
});

test("view not reachable by anon/auth -> no findings", () => {
  const view = {
    view_name: "internal_view",
    security_invoker: false,
    anon_select: false,
    auth_select: false,
    columns: ["id"],
  };
  assert.equal(classifyView(view, null).length, 0);
});

test("view exposing PII columns to anon -> view_exposes_pii_to_anon (critical)", () => {
  const view = {
    view_name: "leaky_pii",
    security_invoker: true, // invoker is fine, but PII still leaks
    anon_select: true,
    columns: ["user_id", "email", "cpf"],
  };
  const findings = classifyView(view, null);
  const pii = findings.find((f) => f.check === "view_exposes_pii_to_anon");
  assert.ok(pii);
  assert.equal(pii.severity, "critical");
  assert.equal(pii.confidence, "inferred");
  assert.deepEqual(pii.evidence.sensitive_columns, ["email", "cpf"]);
});

test("processViews: probes reachable views, collects findings per view", async () => {
  const views = [
    {
      view_name: "leaky_v",
      security_invoker: false,
      anon_select: true,
      columns: ["id", "email"],
      auth_select: false,
      matview: false,
    },
    {
      view_name: "safe_v",
      security_invoker: true,
      anon_select: true,
      columns: ["id"],
      auth_select: false,
      matview: false,
    },
  ];
  const probeFn = async (name) => {
    if (name === "leaky_v") return { status: 200, rowCount: 1, bytes: 100 };
    return { status: 401, rowCount: 0, bytes: 0 };
  };
  const findings = await processViews(views, probeFn);
  // leaky_v: bypass (confirmed, critical — PII+confirmed) + PII exposure (critical)
  const leakyFindings = findings.filter((f) => f.target === "leaky_v");
  assert.ok(leakyFindings.some((f) => f.check === "view_security_definer_bypass"));
  assert.ok(leakyFindings.some((f) => f.check === "view_exposes_pii_to_anon"));
  // safe_v: invoker=true, no PII -> nothing
  assert.equal(findings.filter((f) => f.target === "safe_v").length, 0);
});

test("processViews: no probeFn -> all reachable views get inferred confidence", async () => {
  const views = [
    {
      view_name: "leaky_v",
      security_invoker: false,
      anon_select: true,
      columns: ["id", "email"],
      auth_select: false,
    },
  ];
  const findings = await processViews(views, null);
  assert.equal(findings.length, 2); // bypass + PII
  for (const f of findings) {
    assert.equal(f.confidence, "inferred");
  }
});

// WO-16: security_invoker defaults to false (PG default — view runs as owner).
// A view without an explicit security_invoker value IS a security-definer
// view (bypasses RLS on the base table). The old code defaulted to true,
// making the !security_invoker check unreachable.
test("WO-16: view without security_invoker field defaults to false (definer)", () => {
  const view = {
    view_name: "owner_view",
    anon_select: true,
    columns: [],
    // security_invoker intentionally omitted — should default to false
  };
  const findings = classifyView(view);
  // security_invoker=false → view runs as owner → bypasses RLS
  const bypass = findings.find((f) => f.check === "view_security_definer_bypass");
  assert.ok(bypass, "should flag security-definer view when security_invoker is absent (defaults to false)");
  assert.equal(bypass.details.security_invoker, false);
});
