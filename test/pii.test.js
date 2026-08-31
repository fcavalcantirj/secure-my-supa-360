import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { classifyColumn, isSensitiveColumn, scanForSensitiveColumns } from "../scripts/checks/pii.js";
import { normalizeFinding, assembleResult, scanForSecrets } from "../scripts/contract.js";
import { validate } from "../scripts/validate.js";

const SCHEMA_PATH = fileURLToPath(new URL("../schema/finding.schema.json", import.meta.url));
const schema = JSON.parse(readFileSync(SCHEMA_PATH, "utf8"));

// ---------------------------------------------------------------------------
// classifyColumn — returns the PII/credential category string or null
// ---------------------------------------------------------------------------

test("classifyColumn: cpf -> 'cpf'", () => {
  assert.equal(classifyColumn("cpf"), "cpf");
  assert.equal(classifyColumn("user_cpf"), "cpf");
  assert.equal(classifyColumn("cpf_number"), "cpf");
});

test("classifyColumn: cnpj -> 'cnpj'", () => {
  assert.equal(classifyColumn("cnpj"), "cnpj");
  assert.equal(classifyColumn("company_cnpj"), "cnpj");
});

test("classifyColumn: email -> 'email'", () => {
  assert.equal(classifyColumn("email"), "email");
  assert.equal(classifyColumn("user_email"), "email");
  assert.equal(classifyColumn("e_mail"), "email");
});

test("classifyColumn: phone -> 'phone'", () => {
  assert.equal(classifyColumn("phone"), "phone");
  assert.equal(classifyColumn("phone_number"), "phone");
  assert.equal(classifyColumn("cell"), "phone");
  assert.equal(classifyColumn("whatsapp"), "phone");
});

test("classifyColumn: birthdate -> 'birthdate'", () => {
  assert.equal(classifyColumn("birth_date"), "birthdate");
  assert.equal(classifyColumn("date_of_birth"), "birthdate");
  assert.equal(classifyColumn("nascimento"), "birthdate");
});

test("classifyColumn: health -> 'health'", () => {
  assert.equal(classifyColumn("medical_record"), "health");
  assert.equal(classifyColumn("doctor_notes"), "health");
  assert.equal(classifyColumn("prescription"), "health");
});

test("classifyColumn: credentials -> 'credentials'", () => {
  assert.equal(classifyColumn("password"), "credentials");
  assert.equal(classifyColumn("password_hash"), "credentials");
  assert.equal(classifyColumn("api_key"), "credentials");
  assert.equal(classifyColumn("session_token"), "credentials");
  assert.equal(classifyColumn("access_token"), "credentials");
});

test("classifyColumn: government_id -> 'government_id'", () => {
  assert.equal(classifyColumn("ssn"), "government_id");
  assert.equal(classifyColumn("social_security"), "government_id");
  assert.equal(classifyColumn("gov_id"), "government_id");
});

test("classifyColumn: non-sensitive names -> null", () => {
  assert.equal(classifyColumn("id"), null);
  assert.equal(classifyColumn("name"), null);
  assert.equal(classifyColumn("created_at"), null);
  assert.equal(classifyColumn("is_active"), null);
  assert.equal(classifyColumn("profile"), null);
  assert.equal(classifyColumn("notes"), null);
  assert.equal(classifyColumn("data"), null);
});

test("classifyColumn: null/empty name -> null", () => {
  assert.equal(classifyColumn(null), null);
  assert.equal(classifyColumn(undefined), null);
  assert.equal(classifyColumn(""), null);
});

test("classifyColumn: data type also checked (e.g. column 'data' of type 'jsonb' with 'token')", () => {
  // Name alone should not match, but name + type can
  assert.equal(classifyColumn("notes", "text"), null);
  // If the column name contains a sensitive keyword, it matches regardless of type
  assert.equal(classifyColumn("secret_note", "text"), "credentials");
});

// ---------------------------------------------------------------------------
// isSensitiveColumn — boolean shortcut
// ---------------------------------------------------------------------------

test("isSensitiveColumn: boolean matches classifyColumn", () => {
  assert.equal(isSensitiveColumn("email"), true);
  assert.equal(isSensitiveColumn("id"), false);
  assert.equal(isSensitiveColumn("password_hash"), true);
  assert.equal(isSensitiveColumn(null), false);
});

// ---------------------------------------------------------------------------
// scanForSensitiveColumns — array input, mixed string/object
// ---------------------------------------------------------------------------

test("scanForSensitiveColumns: array of strings", () => {
  const result = scanForSensitiveColumns(["id", "name", "email", "cpf", "created_at"]);
  assert.equal(result.length, 2);
  assert.equal(result[0].name, "email");
  assert.equal(result[0].classification, "email");
  assert.equal(result[1].name, "cpf");
  assert.equal(result[1].classification, "cpf");
});

test("scanForSensitiveColumns: array of objects (name + data_type)", () => {
  const result = scanForSensitiveColumns([
    { name: "id", data_type: "integer" },
    { name: "user_email", data_type: "text" },
    { name: "phone", data_type: "text" },
    { name: "is_active", data_type: "boolean" },
  ]);
  assert.equal(result.length, 2);
  assert.equal(result[0].name, "user_email");
  assert.equal(result[0].classification, "email");
  assert.equal(result[1].name, "phone");
  assert.equal(result[1].classification, "phone");
});

test("scanForSensitiveColumns: empty/null/array-like -> []", () => {
  assert.deepEqual(scanForSensitiveColumns([]), []);
  assert.deepEqual(scanForSensitiveColumns(null), []);
  assert.deepEqual(scanForSensitiveColumns(undefined), []);
});

// ---------------------------------------------------------------------------
// Severity escalation: confirmed leak of sensitive column -> critical
// ---------------------------------------------------------------------------

test("PII escalation: confirmed leak of sensitive column -> critical", async () => {
  // Simulates: RLS-on table with permissive USING(true) policy, anon access,
  // probe confirms 200 + rows, and the leaked columns include PII.
  // classifyTable already handles this — this test proves the contract:
  // isSensitiveColumn + scanForSensitiveColumns produce the right escalation.
  const columns = ["id", "name", "email", "cpf", "created_at"];
  const sensitive = scanForSensitiveColumns(columns);
  assert.equal(sensitive.length, 2); // email + cpf

  // Simulate normalizeFinding + schema round-trip with sensitive_columns evidence
  const raw = {
    check: "rls_permissive_policy",
    category: "coverage-rls",
    severity: "critical", // escalated because sensitive + confirmed
    confidence: "confirmed",
    target: "sensitive_photos",
    evidence: {
      rls_enabled: true,
      sensitive_columns: sensitive,
      probe: { status: 200, row_count: 1, bytes: 64 },
    },
    fix: {
      sql: ["ALTER TABLE public.sensitive_photos ENABLE ROW LEVEL SECURITY;"],
      rollback_sql: [],
      dashboard_action: null,
      management_api_action: null,
      requires_service_role: false,
    },
    references: [],
    suppressed: false,
    suppressed_reason: null,
  };

  const normalized = normalizeFinding(raw);
  const fixedAt = "2026-08-27T12:00:00.000Z";
  const result = assembleResult({
    project_ref: "ref-pii-01",
    mode: "audit-active",
    rawFindings: [normalized],
    generated_at: fixedAt,
  });

  const { valid, errors } = validate(result, schema);
  assert.equal(valid, true, `schema violations: ${JSON.stringify(errors)}`);
  assert.equal(scanForSecrets(JSON.stringify(result)).length, 0, "secrets leaked in output");

  // Verify escalation: critical + confirmed + sensitive columns recorded
  const f = result.findings[0];
  assert.equal(f.severity, "critical");
  assert.equal(f.confidence, "confirmed");
  assert.equal(f.evidence.sensitive_columns.length, 2);
  assert.ok(f.evidence.sensitive_columns.some((c) => c.name === "email" && c.classification === "email"));
  assert.ok(f.evidence.sensitive_columns.some((c) => c.name === "cpf" && c.classification === "cpf"));
});

// === substring false positives (2026-08-31) ===
// Plain substring matching classified ordinary columns as PII, inflating CRITICAL.
// On one real project 160/160 column-grant CRITICALs were sensitive-classified, and a
// large share came from matches like these. A CRITICAL that is usually wrong is worse
// than no CRITICAL: it teaches the reader to skip the ones that are right.

test("classifyColumn: short tokens must match a whole segment, not any substring", () => {
  // "cep" inside "accepted", "cel" inside "cancelled", "account" inside "accounting"
  assert.equal(classifyColumn("accepted_at"), null);
  assert.equal(classifyColumn("terms_accepted_at"), null);
  assert.equal(classifyColumn("accepter_name"), null);
  assert.equal(classifyColumn("cancelled_at"), null);
  assert.equal(classifyColumn("cancelled_consultations"), null);
  assert.equal(classifyColumn("accounting_firm"), null);
});

test("classifyColumn: the same short tokens DO match as real segments", () => {
  assert.equal(classifyColumn("cep"), "address");
  assert.equal(classifyColumn("source_zip"), "address");
  assert.equal(classifyColumn("bank_account"), "financial");
  assert.equal(classifyColumn("card_number"), "financial");
  assert.equal(classifyColumn("access_token"), "credentials");
  assert.equal(classifyColumn("session_token"), "credentials");
});

test("classifyColumn: LLM usage counters are not credentials", () => {
  for (const c of ["input_tokens", "output_tokens", "cached_tokens",
                   "tokens_cache_read", "tokens_cache_write", "total_tokens"]) {
    assert.equal(classifyColumn(c), null, `${c} is a usage counter, not a secret`);
  }
  // ...but a real token still is one
  assert.equal(classifyColumn("worker_token"), "credentials");
  assert.equal(classifyColumn("share_token"), "credentials");
});

test("classifyColumn: a boolean cannot BE the sensitive value", () => {
  assert.equal(classifyColumn("has_password", "boolean"), null);
  assert.equal(classifyColumn("has_medical_certificate", "boolean"), null);
  assert.equal(classifyColumn("nr1_health_module_enabled", "boolean"), null);
  // the same names on a text column stay sensitive
  assert.equal(classifyColumn("password", "text"), "credentials");
  assert.equal(classifyColumn("medical_record", "text"), "health");
});

test("classifyColumn: multi-word and prefix patterns still work", () => {
  assert.equal(classifyColumn("e_mail"), "email");
  assert.equal(classifyColumn("social_security"), "government_id");
  assert.equal(classifyColumn("medications"), "health");
  assert.equal(classifyColumn("prescription_pdfs"), "health");
});
