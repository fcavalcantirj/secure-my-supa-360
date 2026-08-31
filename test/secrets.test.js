import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import {
  scanFile,
  scanRepo,
  decodeJwt,
  jwtRole,
  redact,
} from "../scripts/checks/secrets.js";
import { normalizeFinding, assembleResult, scanForSecrets } from "../scripts/contract.js";
import { validate } from "../scripts/validate.js";

const SCHEMA_PATH = fileURLToPath(new URL("../schema/finding.schema.json", import.meta.url));
const schema = JSON.parse(readFileSync(SCHEMA_PATH, "utf8"));

// --- JWT helpers for tests ---
const b64url = (s) => Buffer.from(s).toString("base64url");
const makeJwt = (payload) =>
  `${b64url('{"alg":"HS256","typ":"JWT"}')}.${b64url(JSON.stringify(payload))}.${"a".repeat(20)}`;

const ANON_JWT = makeJwt({ role: "anon", sub: "anon", aud: "authenticated" });
const SR_JWT = makeJwt({ role: "service_role", sub: "service_role", aud: "supabase" });
const NO_ROLE_JWT = makeJwt({ sub: "something" });

// ---------------------------------------------------------------------------
// decodeJwt / jwtRole / redact
// ---------------------------------------------------------------------------

test("decodeJwt parses the payload", () => {
  const p = decodeJwt(SR_JWT);
  assert.equal(p.role, "service_role");
});

test("jwtRole: service_role / anon / unknown", () => {
  assert.equal(jwtRole(SR_JWT), "service_role");
  assert.equal(jwtRole(ANON_JWT), "anon");
  assert.equal(jwtRole("not-a-jwt"), null);
  assert.equal(jwtRole(NO_ROLE_JWT), null);
});

test("redact truncates to 8 chars + ellipsis (too short to match any secret regex)", () => {
  assert.equal(redact("sbp_abcdefghijklmnopqrstuvwxyz1234567890"), "sbp_abcd…");
  assert.equal(redact("postgresql://u:p@host:5432/db"), "postgres…");
  assert.equal(redact(null), "");
});

// ---------------------------------------------------------------------------
// scanFile — individual secret classes
// ---------------------------------------------------------------------------

test("scanFile: service_role JWT -> committed_service_role_jwt (critical)", () => {
  const findings = scanFile("lib/supabase.js", `export const admin = "${SR_JWT}";`);
  const f = findings.find((x) => x.check === "committed_service_role_jwt");
  assert.ok(f, `expected service_role finding, got: ${findings.map((x) => x.check).join(", ")}`);
  assert.equal(f.severity, "critical");
  assert.equal(f.confidence, "confirmed");
  // preview must be redacted (no full token)
  assert.ok(!JSON.stringify(f.evidence).includes(SR_JWT.slice(10)));
  assert.equal(f.evidence.role, "service_role");
});

test("scanFile: sbp_ PAT -> committed_supabase_pat (critical)", () => {
  const findings = scanFile("utils.js", `const pat = "sbp_abcdefghijklmnopqrstuvwxyz_1234567890";`);
  const f = findings.find((x) => x.check === "committed_supabase_pat");
  assert.ok(f);
  assert.equal(f.severity, "critical");
});

test("scanFile: postgres connstring -> committed_db_connstring (high)", () => {
  const findings = scanFile("db.js", `const url = "postgresql://supabase:secretpassword@db.supabase.co:5432/postgres";`);
  const f = findings.find((x) => x.check === "committed_db_connstring");
  assert.ok(f);
  assert.equal(f.severity, "high");
});

test("scanFile: third-party keys -> committed_thirdparty_key", () => {
  const content = `STRIPE="${"sk_live_" + "1".repeat(24)}"\nAWS=AKIA${"1".repeat(16)}\nGH=ghp_${"a".repeat(36)}`;
  const findings = scanFile(".env", content);
  const kinds = findings.filter((x) => x.check === "committed_thirdparty_key").map((x) => x.evidence.kind);
  assert.ok(kinds.length >= 3, `expected >=3 thirdparty findings, got: ${kinds.join(", ")}`);
  assert.ok(findings.find((x) => x.check === "committed_thirdparty_key" && x.severity === "critical")); // stripe = critical
});

test("scanFile: NEXT_PUBLIC_ holding service_role JWT -> env_secret_exposed_to_browser", () => {
  const findings = scanFile("config.js", `NEXT_PUBLIC_SERVICE_ROLE=${SR_JWT}`);
  const f = findings.find((x) => x.check === "env_secret_exposed_to_browser");
  assert.ok(f, `expected browser-exposure finding, got: ${findings.map((x) => x.check).join(", ")}`);
  assert.equal(f.severity, "critical");
  assert.equal(f.evidence.var, "NEXT_PUBLIC_SERVICE_ROLE");
});

test("scanFile: NEXT_PUBLIC_ holding the public anon key -> NOT flagged (public-by-design)", () => {
  const findings = scanFile("config.js", `NEXT_PUBLIC_SUPABASE_ANON_KEY=${ANON_JWT}`);
  assert.equal(findings.find((x) => x.check === "env_secret_exposed_to_browser"), undefined);
  assert.equal(findings.find((x) => x.check === "committed_service_role_jwt"), undefined);
});

test("scanFile: sb_publishable_ key and legacy anon JWT are NOT findings (public-by-design)", () => {
  const content = `const ANON = "${ANON_JWT}";\nconst PUB = "sb_publishable_${"x".repeat(24)}";`;
  const findings = scanFile("public.js", content);
  assert.equal(findings.length, 0, `expected no findings, got: ${findings.map((x) => x.check).join(", ")}`);
});

// ---------------------------------------------------------------------------
// scanRepo — tracking / .gitignore / golden fixture
// ---------------------------------------------------------------------------

test("scanRepo golden fixture (spec step 5): service_role in tracked file + NEXT_PUBLIC non-anon -> two findings", () => {
  const files = [
    { path: "lib/supabase.js", content: `export const admin = "${SR_JWT}";` },
    { path: "config.js", content: `NEXT_PUBLIC_SERVICE_ROLE=${SR_JWT}` },
  ];
  const { findings } = scanRepo(files, { trackedPaths: ["lib/supabase.js", "config.js"] });
  assert.ok(findings.some((f) => f.check === "committed_service_role_jwt"), "missing committed_service_role_jwt");
  assert.ok(findings.some((f) => f.check === "env_secret_exposed_to_browser"), "missing env_secret_exposed_to_browser");
});

test("scanRepo: .env file that IS tracked -> dotenv_tracked + its secrets", () => {
  const files = [{ path: ".env", content: `SERVICE_ROLE=${SR_JWT}` }];
  const { findings } = scanRepo(files, { trackedPaths: [".env"] });
  assert.ok(findings.some((f) => f.check === "dotenv_tracked"), "missing dotenv_tracked");
  assert.ok(findings.some((f) => f.check === "committed_service_role_jwt"), "missing secret finding");
  // neither suppressed (file is tracked)
  assert.equal(findings.filter((f) => f.check === "committed_service_role_jwt")[0].suppressed, false);
});

test("scanRepo: secret in a gitignored (.env.local, not tracked) file -> suppressed", () => {
  const files = [{ path: ".env.local", content: `SERVICE_ROLE=${SR_JWT}` }];
  const { findings } = scanRepo(files, { trackedPaths: [] });
  const sr = findings.find((f) => f.check === "committed_service_role_jwt");
  assert.ok(sr, "gitignored secret should still appear (suppressed) for auditability");
  assert.equal(sr.suppressed, true);
  assert.equal(findings.find((f) => f.check === "dotenv_tracked"), undefined); // .env.local not tracked -> no hygiene finding
});

test("scanRepo: secret in a non-tracked code file -> suppressed", () => {
  const files = [{ path: "leak.ts", content: `export const x = "sbp_abcdefghijklmnopqrstuvwxyz_1234567890";` }];
  const { findings } = scanRepo(files, { trackedPaths: [] });
  const pat = findings.find((f) => f.check === "committed_supabase_pat");
  assert.ok(pat);
  assert.equal(pat.suppressed, true);
});

test("scanRepo: context notes legacy JWT anon key format (not a finding)", () => {
  const files = [{ path: ".env", content: `NEXT_PUBLIC_SUPABASE_ANON_KEY=${ANON_JWT}\nNEXT_PUBLIC_PUBLISHABLE=sb_publishable_${"y".repeat(24)}` }];
  const { findings, context } = scanRepo(files, { trackedPaths: [".env"] });
  // No secret findings (anon key is public-by-design)
  assert.equal(findings.filter((f) => f.suppressed !== true).length, 1); // only dotenv_tracked
  assert.ok(findings.some((f) => f.check === "dotenv_tracked"));
  assert.equal(context.anon_key_format, "sb_publishable_ (modern, public-by-design)");
});

// ---------------------------------------------------------------------------
// Full contract round-trip
// ---------------------------------------------------------------------------

test("secrets scan round-trip: normalize -> assembleResult -> schema valid + no secrets + deterministic", () => {
  const files = [
    { path: "lib/supabase.js", content: `export const admin = "${SR_JWT}";` },
    { path: "config.js", content: `NEXT_PUBLIC_SERVICE_ROLE=${SR_JWT}` },
    { path: ".env.local", content: `PAT=sbp_${"a".repeat(28)}` }, // gitignored -> suppressed
  ];
  const { findings: raw } = scanRepo(files, { trackedPaths: ["lib/supabase.js", "config.js"] });
  const normalized = raw.map(normalizeFinding);

  const fixedAt = "2026-08-27T12:00:00.000Z";
  const opts = { project_ref: "ref-sec-01", mode: "discover", rawFindings: normalized, generated_at: fixedAt };

  const result = assembleResult(opts);
  const { valid, errors } = validate(result, schema);
  assert.equal(valid, true, `schema violations: ${JSON.stringify(errors)}`);

  const jsonStr = JSON.stringify(result);
  assert.equal(scanForSecrets(jsonStr).length, 0, `secrets leaked in output`);

  const json1 = JSON.stringify(assembleResult(opts), null, 2);
  const json2 = JSON.stringify(assembleResult(opts), null, 2);
  assert.equal(json1, json2, "output must be deterministic");

  // suppressed (gitignored) findings still present, auditable
  const suppressed = result.findings.filter((f) => f.suppressed);
  assert.ok(suppressed.length >= 1, "suppressed findings should remain in output");
});
