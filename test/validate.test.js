import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { validate } from "../scripts/validate.js";

const SCHEMA_PATH = fileURLToPath(new URL("../schema/finding.schema.json", import.meta.url));
const schema = JSON.parse(readFileSync(SCHEMA_PATH, "utf8"));

// A valid contract result with one finding
const baseResult = {
  schema_version: "1.0",
  project_ref: "abc123def456",
  project_name: "My App",
  region: "us-east-1",
  generated_at: "2026-08-27T12:00:00.000Z",
  mode: "audit-active",
  summary: {
    by_severity: { critical: 1, high: 0, medium: 0, low: 0, info: 0 },
    confirmed: 1,
    inferred: 0,
    suppressed: 0,
  },
  findings: [
    {
      id: "abc123def456",
      check: "rls_disabled",
      category: "coverage-rls",
      severity: "critical",
      confidence: "confirmed",
      target: "leaky_table",
      evidence: { rls_enabled: false, anon_select: true },
      probe: {
        status: 200,
        bytes: 512,
        sample: { row_count: 3, columns: ["id", "name"] },
      },
      fix: {
        sql: ["ALTER TABLE public.leaky_table ENABLE ROW LEVEL SECURITY;"],
        rollback_sql: [],
        dashboard_action: null,
        management_api_action: null,
        requires_service_role: false,
      },
      references: ["https://supabase.com/docs/guides/auth/row-level-security"],
      suppressed: false,
      suppressed_reason: null,
      title: "RLS disabled on table accessible via anon",
      explain: "Without RLS, anon role with default CRUD grants can read/insert/delete any row.",
      fix_sql: "ALTER TABLE public.leaky_table ENABLE ROW LEVEL SECURITY;",
    },
  ],
};

test("valid result passes schema validation", () => {
  const { valid, errors } = validate(baseResult, schema);
  assert.equal(valid, true, `expected valid but got errors: ${JSON.stringify(errors)}`);
  assert.equal(errors.length, 0);
});

test("missing schema_version violates schema", () => {
  const r = { ...baseResult };
  delete r.schema_version;
  const { valid, errors } = validate(r, schema);
  assert.equal(valid, false);
  assert.ok(errors.some((e) => e.path.includes("schema_version") && e.message.includes("missing")));
});

test("wrong schema_version const violates schema", () => {
  const r = { ...baseResult, schema_version: "2.0" };
  const { valid, errors } = validate(r, schema);
  assert.equal(valid, false);
  assert.ok(errors.some((e) => e.path.includes("schema_version")));
});

test("missing required finding fields violate schema", () => {
  const r = { ...baseResult, findings: [{ check: "x" }] };
  const { valid, errors } = validate(r, schema);
  assert.equal(valid, false);
  assert.ok(errors.some((e) => e.message.includes("missing required property")));
});

test("invalid severity enum violates schema", () => {
  const r = {
    ...baseResult,
    findings: [{ ...baseResult.findings[0], severity: "urgent" }],
  };
  const { valid, errors } = validate(r, schema);
  assert.equal(valid, false);
  assert.ok(errors.some((e) => e.message.includes("enum")));
});

test("invalid confidence enum violates schema", () => {
  const r = {
    ...baseResult,
    findings: [{ ...baseResult.findings[0], confidence: "maybe" }],
  };
  const { valid, errors } = validate(r, schema);
  assert.equal(valid, false);
  assert.ok(errors.some((e) => e.message.includes("enum")));
});

test("probe can be null (no active probe)", () => {
  const r = {
    ...baseResult,
    findings: [{ ...baseResult.findings[0], probe: null }],
  };
  const { valid, errors } = validate(r, schema);
  assert.equal(valid, true, `expected valid: ${JSON.stringify(errors)}`);
});

test("summary requires all severity keys", () => {
  const r = {
    ...baseResult,
    summary: { by_severity: { critical: 0, high: 0, medium: 0, low: 0 }, confirmed: 0, inferred: 0, suppressed: 0 },
  };
  const { valid, errors } = validate(r, schema);
  assert.equal(valid, false);
  assert.ok(errors.some((e) => e.path.includes("info")));
});

test("management_api_action can be an object", () => {
  const r = {
    ...baseResult,
    findings: [
      {
        ...baseResult.findings[0],
        fix: {
          sql: [],
          rollback_sql: [],
          dashboard_action: null,
          management_api_action: { method: "PATCH", path: "/v1/projects/ref/config/auth", body: { mailer_autoconfirm: false } },
          requires_service_role: false,
        },
      },
    ],
  };
  const { valid, errors } = validate(r, schema);
  assert.equal(valid, true, `expected valid: ${JSON.stringify(errors)}`);
});

test("empty findings array is valid (clean project)", () => {
  const r = {
    ...baseResult,
    summary: { by_severity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 }, confirmed: 0, inferred: 0, suppressed: 0 },
    findings: [],
  };
  const { valid, errors } = validate(r, schema);
  assert.equal(valid, true, `expected valid: ${JSON.stringify(errors)}`);
});

test("mode accepts audit-active, audit-passive, discover", () => {
  for (const mode of ["audit-active", "audit-passive", "discover"]) {
    const r = { ...baseResult, mode };
    const { valid, errors } = validate(r, schema);
    assert.equal(valid, true, `mode ${mode} should be valid: ${JSON.stringify(errors)}`);
  }
});

test("invalid mode enum violates schema", () => {
  const r = { ...baseResult, mode: "live" };
  const { valid, errors } = validate(r, schema);
  assert.equal(valid, false);
  assert.ok(errors.some((e) => e.message.includes("enum")));
});

// Regression: nested $ref chain result -> finding -> fix must resolve against
// the root schema. Before validate.js threaded `root` explicitly, resolveRef
// could fail on double-nested refs (e.g. finding.fix -> #/$defs/fix).
test("nested $ref (finding -> $defs/fix) resolves against root", () => {
  const r = {
    ...baseResult,
    findings: [
      {
        id: "abc123def456-fix-nested",
        check: "auth_mfa_disabled",
        category: "coverage-auth",
        severity: "high",
        confidence: "confirmed",
        target: "auth_config",
        evidence: { mfa_enabled: false },
        probe: { status: 200, bytes: 0, sample: null },
        fix: {
          sql: [],
          rollback_sql: [],
          dashboard_action: null,
          management_api_action: {
            method: "PATCH",
            path: "/v1/projects/abc123def456/config/auth",
            body: { security_mfa_enabled: true },
          },
          requires_service_role: false,
        },
        references: ["https://supabase.com/docs/guides/auth/mfa"],
        suppressed: false,
        suppressed_reason: null,
        title: "MFA disabled",
        explain: "Multi-factor auth is not enforced",
        fix_sql: null,
      },
    ],
  };
  const { valid, errors } = validate(r, schema);
  assert.equal(valid, true, `expected valid but got: ${JSON.stringify(errors)}`);
});
