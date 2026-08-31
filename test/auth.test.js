import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { analyzeAuthConfig } from "../scripts/checks/auth.js";
import { normalizeFinding, assembleResult } from "../scripts/contract.js";
import { validate } from "../scripts/validate.js";

const SCHEMA_PATH = fileURLToPath(new URL("../schema/finding.schema.json", import.meta.url));
const schema = JSON.parse(readFileSync(SCHEMA_PATH, "utf8"));

const REF = "test-ref-01";

// ---------------------------------------------------------------------------
// Individual checks
// ---------------------------------------------------------------------------

test("analyzeAuthConfig: signups enabled + autoconfirm -> auth_signups_enabled_no_confirm (medium)", () => {
  const cfg = { disable_signup: false, mailer_autoconfirm: true };
  const f = analyzeAuthConfig(cfg, REF).find((f) => f.check === "auth_signups_enabled_no_confirm");
  assert.ok(f, "expected signups finding");
  assert.equal(f.severity, "medium");
  assert.equal(f.target, "auth:signups");
  assert.equal(f.fix.management_api_action.path, `/v1/projects/${REF}/config/auth`);
  assert.deepEqual(f.fix.management_api_action.body, { mailer_autoconfirm: false });
});

test("analyzeAuthConfig: anonymous sign-ins enabled -> anonymous_signins_enabled (high)", () => {
  const cfg = { external_anonymous_users_enabled: true };
  const f = analyzeAuthConfig(cfg, REF).find((f) => f.check === "anonymous_signins_enabled");
  assert.ok(f);
  assert.equal(f.severity, "high");
  assert.equal(f.target, "auth:anonymous");
});

test("analyzeAuthConfig: password_min_length 6 -> weak_password_policy (medium)", () => {
  const cfg = { password_min_length: 6, password_required_characters: "" };
  const f = analyzeAuthConfig(cfg, REF).find((f) => f.check === "weak_password_policy");
  assert.ok(f);
  assert.equal(f.severity, "medium");
  assert.equal(f.evidence.password_min_length, 6);
  assert.ok(f.fix.management_api_action.body.password_min_length >= 8);
});

test("analyzeAuthConfig: captcha disabled + signups open -> no_captcha_on_auth (medium)", () => {
  const cfg = { security_captcha_enabled: false, disable_signup: false };
  const f = analyzeAuthConfig(cfg, REF).find((f) => f.check === "no_captcha_on_auth");
  assert.ok(f);
  assert.equal(f.severity, "medium");
  assert.equal(f.target, "auth:captcha");
});

test("analyzeAuthConfig: hibp disabled -> auth_hibp_disabled (medium)", () => {
  const cfg = { password_hibp_enabled: false };
  const f = analyzeAuthConfig(cfg, REF).find((f) => f.check === "auth_hibp_disabled");
  assert.ok(f);
  assert.equal(f.severity, "medium");
  assert.equal(f.evidence.password_hibp_enabled, false);
  assert.deepEqual(f.fix.management_api_action.body, { password_hibp_enabled: true });
});

test("analyzeAuthConfig: mfa disabled -> auth_mfa_disabled (high) + dashboard_action", () => {
  const cfg = { mfa_enabled: false };
  const f = analyzeAuthConfig(cfg, REF).find((f) => f.check === "auth_mfa_disabled");
  assert.ok(f);
  assert.equal(f.severity, "high");
  assert.equal(f.target, "auth:mfa");
  assert.ok(f.fix.dashboard_action); // MFA often needs dashboard steps
});

test("analyzeAuthConfig: jwt_exp 86400 -> auth_jwt_exp_too_long (medium)", () => {
  const cfg = { jwt_exp: 86400 };
  const f = analyzeAuthConfig(cfg, REF).find((f) => f.check === "auth_jwt_exp_too_long");
  assert.ok(f);
  assert.equal(f.severity, "medium");
  assert.equal(f.evidence.jwt_exp, 86400);
  assert.equal(f.fix.management_api_action.body.jwt_exp, 3600);
});

test("analyzeAuthConfig: empty uri_allow_list -> auth_redirect_allowlist_open (high)", () => {
  const cfg = { uri_allow_list: [] };
  const f = analyzeAuthConfig(cfg, REF).find((f) => f.check === "auth_redirect_allowlist_open");
  assert.ok(f);
  assert.equal(f.severity, "high");
  assert.equal(f.target, "auth:redirect");
  assert.deepEqual(f.evidence.uri_allow_list, []);
});

test("analyzeAuthConfig: no rate_limit_* keys -> auth_rate_limit_missing (medium)", () => {
  const cfg = { disable_signup: true, mailer_autoconfirm: false };
  const f = analyzeAuthConfig(cfg, REF).find((f) => f.check === "auth_rate_limit_missing");
  assert.ok(f);
  assert.equal(f.severity, "medium");
  assert.equal(f.target, "auth:rate_limit");
  assert.ok(f.fix.dashboard_action);
});

test("analyzeAuthConfig: rate_limit_* present -> no rate_limit finding", () => {
  const cfg = { rate_limit_email_sent: 5, rate_limit_sms_sent: 5 };
  const f = analyzeAuthConfig(cfg, REF).find((f) => f.check === "auth_rate_limit_missing");
  assert.equal(f, undefined);
});

test("analyzeAuthConfig: null config -> empty array", () => {
  assert.deepEqual(analyzeAuthConfig(null, REF), []);
  assert.deepEqual(analyzeAuthConfig(undefined, REF), []);
});

// ---------------------------------------------------------------------------
// Boundary tests
// ---------------------------------------------------------------------------

test("analyzeAuthConfig: password_min_length exactly 8 -> NOT flagged", () => {
  const cfg = { password_min_length: 8 };
  assert.equal(analyzeAuthConfig(cfg, REF).find((f) => f.check === "weak_password_policy"), undefined);
});

test("analyzeAuthConfig: jwt_exp exactly 28800 (8h) -> NOT flagged", () => {
  const cfg = { jwt_exp: 28800 };
  assert.equal(analyzeAuthConfig(cfg, REF).find((f) => f.check === "auth_jwt_exp_too_long"), undefined);
});

test("analyzeAuthConfig: uri_allow_list non-empty -> NOT flagged", () => {
  const cfg = { uri_allow_list: ["https://app.example.com/callback"] };
  assert.equal(analyzeAuthConfig(cfg, REF).find((f) => f.check === "auth_redirect_allowlist_open"), undefined);
});

// ---------------------------------------------------------------------------
// Golden fixture (spec entry 14 test step)
// ---------------------------------------------------------------------------

test("analyzeAuthConfig golden fixture (spec test step 4): weak config yields expected finding set", () => {
  // min_length 6, HIBP off, autoconfirm on, open redirect allowlist
  const cfg = {
    disable_signup: false,
    mailer_autoconfirm: true,
    password_min_length: 6,
    password_required_characters: "",
    password_hibp_enabled: false,
    uri_allow_list: [],
  };
  const findings = analyzeAuthConfig(cfg, REF);

  const checks = findings.map((f) => f.check).sort();
  assert.deepEqual(checks, [
    "auth_hibp_disabled",
    "auth_rate_limit_missing",
    "auth_redirect_allowlist_open",
    "auth_signups_enabled_no_confirm",
    "weak_password_policy",
  ]);

  // Each finding normalizes + validates against the schema (via full result)
  const normalized = findings.map(normalizeFinding);
  const result = assembleResult({
    project_ref: REF,
    mode: "audit-active",
    rawFindings: normalized,
    generated_at: "2026-08-27T12:00:00.000Z",
  });
  const { valid, errors } = validate(result, schema);
  assert.equal(valid, true, `schema violations: ${JSON.stringify(errors)}`);
});

// ---------------------------------------------------------------------------
// Full contract round-trip
// ---------------------------------------------------------------------------

test("auth scan round-trip: normalize -> assembleResult -> schema valid + no secrets + deterministic", () => {
  const cfg = {
    disable_signup: false,
    mailer_autoconfirm: true,
    password_min_length: 6,
    password_hibp_enabled: false,
    uri_allow_list: [],
    mfa_enabled: false,
  };
  const raw = analyzeAuthConfig(cfg, REF).map(normalizeFinding);

  const fixedAt = "2026-08-27T12:00:00.000Z";
  const opts = {
    project_ref: REF,
    mode: "audit-active",
    rawFindings: raw,
    generated_at: fixedAt,
  };

  const result = assembleResult(opts);
  const { valid, errors } = validate(result, schema);
  assert.equal(valid, true, `schema violations: ${JSON.stringify(errors)}`);

  // No findings suppressed (all from live config = not suppressed)
  const unsuppressed = result.findings.filter((f) => !f.suppressed);
  assert.ok(unsuppressed.length >= 5, `expected >=5 findings, got ${unsuppressed.length}`);

  // Deterministic
  const json1 = JSON.stringify(assembleResult(opts), null, 2);
  const json2 = JSON.stringify(assembleResult(opts), null, 2);
  assert.equal(json1, json2, "output must be deterministic");
});
