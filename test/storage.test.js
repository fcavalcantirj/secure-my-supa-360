import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import {
  classifyBucket,
  processStorage,
  extractBucketIds,
  policyCoversBucket,
  policyGrantsAnon,
  isPathScoped,
  isSensitiveBucket,
  isBucketMisconfigured,
  findBucketConfigIssues,
} from "../scripts/checks/storage.js";
import { normalizeFinding, assembleResult, scanForSecrets } from "../scripts/contract.js";
import { validate } from "../scripts/validate.js";

const SCHEMA_PATH = fileURLToPath(new URL("../schema/finding.schema.json", import.meta.url));
const schema = JSON.parse(readFileSync(SCHEMA_PATH, "utf8"));

// ---------------------------------------------------------------------------
// Helpers / unit predicates
// ---------------------------------------------------------------------------

const ANON_READ_POLICY = (bucket) => ({
  policyname: "anon_read",
  cmd: "SELECT",
  roles: ["public"],
  qual: `bucket_id = '${bucket}'`,
  with_check: null,
});
const ANON_INSERT_POLICY = (bucket) => ({
  policyname: "anon_insert",
  cmd: "INSERT",
  roles: ["anon"],
  qual: null,
  with_check: `bucket_id = '${bucket}'`,
});
const ANON_DELETE_POLICY = (bucket) => ({
  policyname: "anon_delete",
  cmd: "DELETE",
  roles: ["anon"],
  qual: `bucket_id = '${bucket}'`,
  with_check: null,
});

test("extractBucketIds: null expr -> null (covers all buckets)", () => {
  assert.equal(extractBucketIds(null), null);
  assert.equal(extractBucketIds(undefined), null);
  assert.equal(extractBucketIds(""), null);
});

test("extractBucketIds: 'true' -> null (unscoped, covers all)", () => {
  assert.equal(extractBucketIds("true"), null);
  assert.equal(extractBucketIds("(true)"), null);
});

test("extractBucketIds: bucket_id = 'X' -> [X]", () => {
  assert.deepEqual(extractBucketIds("bucket_id = 'media'"), ["media"]);
  assert.deepEqual(extractBucketIds("bucket_id = 'media' AND auth.uid() IS NOT NULL"), ["media"]);
});

test("extractBucketIds: bucket_id IN (...) -> multiple", () => {
  assert.deepEqual(extractBucketIds("bucket_id IN ('a', 'b', 'c')"), ["a", "b", "c"]);
});

test("policyCoversBucket: unscoped policy covers every bucket", () => {
  const p = { qual: "true", with_check: null, roles: ["public"], cmd: "ALL" };
  assert.equal(policyCoversBucket(p, "bucket-a"), true);
  assert.equal(policyCoversBucket(p, "bucket-b"), true);
});

test("policyGrantsAnon: public/anon roles grant anon; authenticated-only does not", () => {
  assert.equal(policyGrantsAnon({ roles: ["public"], cmd: "SELECT" }), true);
  assert.equal(policyGrantsAnon({ roles: ["anon"], cmd: "INSERT" }), true);
  assert.equal(policyGrantsAnon({ roles: ["authenticated"], cmd: "SELECT" }), false);
  assert.equal(policyGrantsAnon({ roles: [], cmd: "SELECT" }), false);
});

test("isPathScoped: foldername / path_tokens / name LIKE => scoped", () => {
  assert.equal(isPathScoped("storage.foldername(name) LIKE 'public/%'"), true);
  assert.equal(isPathScoped("name LIKE 'uploads/%'"), true);
  assert.equal(isPathScoped("path_tokens[1] = 'public'"), true);
  assert.equal(isPathScoped("bucket_id = 'media'"), false);
});

test("isSensitiveBucket: PII-ish names are sensitive", () => {
  assert.equal(isSensitiveBucket("media"), false);
  assert.equal(isSensitiveBucket("uploads"), false);
  assert.equal(isSensitiveBucket("user_emails"), true);
  assert.equal(isSensitiveBucket("cpf_attachments"), true);
});

// ---------------------------------------------------------------------------
// classifyBucket
// ---------------------------------------------------------------------------

test("private bucket (no anon policies) -> no findings", () => {
  const b = { id: "media", name: "media", public: false };
  const policies = [
    { policyname: "owner_only", cmd: "ALL", roles: ["authenticated"], qual: `bucket_id = 'media'`, with_check: null },
  ];
  assert.equal(classifyBucket(b, policies, null).length, 0);
});

test("non-sensitive public bucket, bucket-scoped SELECT -> unscoped-path only, no read (entry 12 covers public read)", () => {
  const b = { id: "media", name: "media", public: true };
  const policies = [ANON_READ_POLICY("media")];
  const findings = classifyBucket(b, policies, null);
  assert.equal(findings.find((f) => f.check === "storage_objects_anon_read"), undefined);
  const unscoped = findings.find((f) => f.check === "storage_policy_unscoped_path");
  assert.ok(unscoped, `expected unscoped-path finding, got: ${findings.map((f) => f.check).join(", ")}`);
  assert.equal(unscoped.severity, "medium");
});

test("sensitive bucket + confirmed read probe -> anon_read (critical, confirmed)", () => {
  const b = { id: "user_emails", name: "user_emails", public: true };
  const policies = [ANON_READ_POLICY("user_emails")];
  const probe = { list: 200, download: 200, upload: 0, delete: 0, listed: 4, bytes: 1024 };
  const findings = classifyBucket(b, policies, probe);
  const read = findings.find((f) => f.check === "storage_objects_anon_read");
  assert.ok(read, `expected read finding, got: ${findings.map((f) => f.check).join(", ")}`);
  assert.equal(read.confidence, "confirmed");
  assert.equal(read.severity, "critical"); // sensitive + confirmed
  assert.deepEqual(read.probe, { status: 200, row_count: 4, bytes: 1024 });
  assert.equal(read.evidence.storage_probe.list, 200);
  assert.equal(read.evidence.storage_probe.listed, 4);
});

test("anon INSERT policy -> storage_objects_anon_insert (critical, inferred)", () => {
  const b = { id: "media", name: "media", public: false };
  const policies = [ANON_INSERT_POLICY("media")];
  const findings = classifyBucket(b, policies, null);
  const ins = findings.find((f) => f.check === "storage_objects_anon_insert");
  assert.ok(ins, `expected insert finding, got: ${findings.map((f) => f.check).join(", ")}`);
  assert.equal(ins.severity, "critical");
  assert.equal(ins.confidence, "inferred");
  assert.equal(ins.probe, null);
});

test("anon DELETE policy -> storage_objects_anon_tamper (critical, inferred)", () => {
  const b = { id: "media", name: "media", public: false };
  const policies = [ANON_DELETE_POLICY("media")];
  const findings = classifyBucket(b, policies, null);
  const tamper = findings.find((f) => f.check === "storage_objects_anon_tamper");
  assert.ok(tamper, `expected tamper finding, got: ${findings.map((f) => f.check).join(", ")}`);
  assert.equal(tamper.severity, "critical");
  assert.equal(tamper.confidence, "inferred");
});

test("confirmed upload + delete probes upgrade insert/tamper to confirmed", () => {
  const b = { id: "media", name: "media", public: false };
  const policies = [ANON_INSERT_POLICY("media"), ANON_DELETE_POLICY("media")];
  const probe = { list: 401, download: 401, upload: 201, delete: 204, listed: 0, bytes: 0 };
  const findings = classifyBucket(b, policies, probe);
  assert.equal(findings.find((f) => f.check === "storage_objects_anon_insert").confidence, "confirmed");
  assert.equal(findings.find((f) => f.check === "storage_objects_anon_tamper").confidence, "confirmed");
});

test("path-scoped SELECT on a sensitive bucket -> read fires, no unscoped-path", () => {
  const b = { id: "user_emails", name: "user_emails", public: false };
  const policies = [
    {
      policyname: "scoped_read",
      cmd: "SELECT",
      roles: ["public"],
      qual: "bucket_id = 'user_emails' AND storage.foldername(name) LIKE 'public/%'",
      with_check: null,
    },
  ];
  const findings = classifyBucket(b, policies, null);
  const read = findings.find((f) => f.check === "storage_objects_anon_read");
  assert.ok(read, `expected read finding, got: ${findings.map((f) => f.check).join(", ")}`);
  assert.equal(read.severity, "high"); // sensitive but not confirmed
  assert.equal(findings.find((f) => f.check === "storage_policy_unscoped_path"), undefined);
});

test("GOLDEN fixture (spec step 5): ALL public+unscoped policy + probe -> read+insert+tamper+unscoped", () => {
  const b = { id: "uploads", name: "uploads", public: true };
  const policies = [
    {
      policyname: "allow_all",
      cmd: "ALL",
      roles: ["public"],
      qual: "true", // no bucket/path scoping
      with_check: null,
    },
  ];
  const probe = { list: 200, download: 200, upload: 201, delete: 404, listed: 3, bytes: 512 };
  const findings = classifyBucket(b, policies, probe);
  const checks = findings.map((f) => f.check);
  assert.ok(checks.includes("storage_objects_anon_read"), `missing read: ${checks.join(", ")}`);
  assert.ok(checks.includes("storage_objects_anon_insert"), `missing insert: ${checks.join(", ")}`);
  assert.ok(checks.includes("storage_objects_anon_tamper"), `missing tamper: ${checks.join(", ")}`);
  assert.ok(checks.includes("storage_policy_unscoped_path"), `missing unscoped: ${checks.join(", ")}`);
  assert.equal(findings.find((f) => f.check === "storage_objects_anon_read").confidence, "confirmed");
  assert.equal(findings.find((f) => f.check === "storage_objects_anon_insert").confidence, "confirmed");
});

// ---------------------------------------------------------------------------
// processStorage + full schema round-trip
// ---------------------------------------------------------------------------

test("processStorage: probes each bucket, collects findings, isolates a failed probe", async () => {
  const buckets = [
    { id: "media", name: "media", public: true }, // bucket-scoped SELECT -> unscoped-path only
    { id: "private", name: "private", public: false }, // anon INSERT (bucket-scoped, not path-scoped)
  ];
  const policies = [ANON_READ_POLICY("media"), ANON_INSERT_POLICY("private")];
  const probeFn = async (bucketId) => {
    if (bucketId === "media") return { list: 200, download: 200, upload: 0, delete: 0, listed: 2, bytes: 256 };
    throw new Error("boom"); // probe failure must NOT abort the run
  };
  const rawFindings = await processStorage(buckets, policies, probeFn);
  // media: bucket-scoped SELECT (non-sensitive) -> no read finding, but unscoped-path warning.
  // private: anon INSERT -> insert finding (inferred, probe threw) + its own unscoped-path warning
  // (bucket-scoped write policy lacks path/foldername scoping).
  assert.equal(rawFindings.length, 3, `expected 3 findings, got: ${rawFindings.map((f) => f.check).join(", ")}`);
  const mediaUn = rawFindings.find((f) => f.target === "bucket:media" && f.check === "storage_policy_unscoped_path");
  assert.ok(mediaUn);
  const privInsert = rawFindings.find((f) => f.target === "bucket:private" && f.check === "storage_objects_anon_insert");
  assert.ok(privInsert);
  assert.equal(privInsert.confidence, "inferred"); // probe threw -> inferred
  const privUn = rawFindings.find((f) => f.target === "bucket:private" && f.check === "storage_policy_unscoped_path");
  assert.ok(privUn, "bucket-scoped anon INSERT without path scoping should also raise unscoped-path");
});

test("processStorage: no probeFn -> all findings are inferred", async () => {
  const buckets = [{ id: "media", name: "media", public: true }];
  const policies = [ANON_INSERT_POLICY("media")];
  const rawFindings = await processStorage(buckets, policies, null);
  assert.ok(rawFindings.length > 0);
  assert.ok(rawFindings.every((f) => f.confidence === "inferred"));
});

test("storage findings round-trip: normalize -> assembleResult -> schema valid + no secrets + deterministic", async () => {
  const buckets = [
    { id: "user_emails", name: "user_emails", public: true },
    { id: "media", name: "media", public: false },
  ];
  const policies = [
    ANON_READ_POLICY("user_emails"),
    ANON_INSERT_POLICY("media"),
    ANON_DELETE_POLICY("media"),
  ];
  const probeFn = async () => ({ list: 200, download: 200, upload: 201, delete: 404, listed: 5, bytes: 800 });

  const raw = await processStorage(buckets, policies, probeFn);
  const normalized = raw.map(normalizeFinding);

  const fixedAt = "2026-08-27T12:00:00.000Z";
  const opts = { project_ref: "ref-stor-01", mode: "audit-active", rawFindings: normalized, generated_at: fixedAt };

  // 1. schema valid
  const result = assembleResult(opts);
  const { valid, errors } = validate(result, schema);
  assert.equal(valid, true, `schema violations: ${JSON.stringify(errors)}`);

  // 2. no secrets in output
  const secrets = scanForSecrets(JSON.stringify(result));
  assert.equal(secrets.length, 0, `secrets found: ${JSON.stringify(secrets)}`);

  // 3. deterministic ordering — same inputs + fixed timestamp => identical JSON
  const json1 = JSON.stringify(assembleResult(opts), null, 2);
  const json2 = JSON.stringify(assembleResult(opts), null, 2);
  assert.equal(json1, json2, "output must be deterministic");

  // 4. every finding has a populated, valid fix object
  for (const f of result.findings) {
    assert.ok(Array.isArray(f.fix.sql), `fix.sql missing on ${f.check}`);
    assert.ok(Array.isArray(f.fix.rollback_sql), `fix.rollback_sql missing on ${f.check}`);
  }
});

// ---------------------------------------------------------------------------
// Entry 12: bucket config hygiene (isBucketMisconfigured + findBucketConfigIssues)
// ---------------------------------------------------------------------------

test("isBucketMisconfigured: null file_size_limit + null allowed_mime_types -> misconfigured", () => {
  const b = { id: "b1", name: "media", public: false, file_size_limit: null, allowed_mime_types: null };
  const issues = isBucketMisconfigured(b);
  assert.ok(issues, "expected misconfigured");
  assert.equal(issues.file_size_limit_missing, true);
  assert.equal(issues.mime_types_missing, true);
});

test("isBucketMisconfigured: both set -> null (not misconfigured)", () => {
  const b = { id: "b1", name: "media", public: true, file_size_limit: 33554432, allowed_mime_types: ["image/*"] };
  assert.equal(isBucketMisconfigured(b), null);
});

test("isBucketMisconfigured: wildcard mime '*/*' -> permissive", () => {
  const b = { id: "b1", name: "media", file_size_limit: 100, allowed_mime_types: ["*/*"] };
  const issues = isBucketMisconfigured(b);
  assert.ok(issues);
  assert.equal(issues.permissive, true);
});

test("isBucketMisconfigured: only file_size_limit missing (mime types set) -> still flagged", () => {
  const b = { id: "b1", name: "docs", file_size_limit: null, allowed_mime_types: ["application/pdf"] };
  const issues = isBucketMisconfigured(b);
  assert.ok(issues);
  assert.equal(issues.file_size_limit_missing, true);
  assert.equal(issues.mime_types_missing, false);
  assert.equal(issues.permissive, false);
});

test("isBucketMisconfigured: only allowed_mime_types missing -> still flagged", () => {
  const b = { id: "b1", name: "docs", file_size_limit: 33554432, allowed_mime_types: [] };
  const issues = isBucketMisconfigured(b);
  assert.ok(issues);
  assert.equal(issues.file_size_limit_missing, false);
  assert.equal(issues.mime_types_missing, true);
});

test("isBucketMisconfigured: null input -> null", () => {
  assert.equal(isBucketMisconfigured(null), null);
  assert.equal(isBucketMisconfigured(undefined), null);
});

test("findBucketConfigIssues: mixed buckets -> only misconfigured flagged", () => {
  const buckets = [
    { id: "b1", name: "media", public: true, file_size_limit: 33554432, allowed_mime_types: ["image/*"] },
    { id: "b2", name: "uploads", public: false, file_size_limit: null, allowed_mime_types: null },
    { id: "b3", name: "avatars", public: true, file_size_limit: null, allowed_mime_types: ["image/png"] },
  ];
  const findings = findBucketConfigIssues(buckets);
  const targets = findings.map((f) => f.target).sort();
  assert.deepEqual(targets, ["bucket:b2", "bucket:b3"]);
});

test("findBucketConfigIssues: all configured -> []", () => {
  const buckets = [
    { id: "b1", name: "media", public: true, file_size_limit: 33554432, allowed_mime_types: ["image/*"] },
    { id: "b2", name: "docs", public: false, file_size_limit: 10485760, allowed_mime_types: ["application/pdf"] },
  ];
  assert.equal(findBucketConfigIssues(buckets).length, 0);
});

test("findBucketConfigIssues: empty/null -> []", () => {
  assert.deepEqual(findBucketConfigIssues([]), []);
  assert.deepEqual(findBucketConfigIssues([null, {}]), []);
});

test("findBucketConfigIssues: public+non-sensitive -> medium, private -> low, public+sensitive(name with PII) -> high", () => {
  const buckets = [
    { id: "b1", name: "media", public: true, file_size_limit: null, allowed_mime_types: null },       // medium
    { id: "b2", name: "docs", public: false, file_size_limit: null, allowed_mime_types: null },       // low
    { id: "b3", name: "cpf_docs", public: true, file_size_limit: null, allowed_mime_types: null },    // high (sensitive name)
  ];
  const findings = findBucketConfigIssues(buckets);
  const byCheck = Object.fromEntries(findings.map((f) => [f.target, f.severity]));
  assert.equal(findings.length, 3);
  assert.equal(findings.find((f) => f.target === "bucket:b1").severity, "medium");
  assert.equal(findings.find((f) => f.target === "bucket:b2").severity, "low");
  assert.equal(findings.find((f) => f.target === "bucket:b3").severity, "high");
});

test("findBucketConfigIssues round-trip: normalize -> assembleResult -> schema valid + no secrets + deterministic", () => {
  const buckets = [
    { id: "b1", name: "uploads", public: true, file_size_limit: null, allowed_mime_types: null },
    { id: "b2", name: "media", public: true, file_size_limit: 33554432, allowed_mime_types: ["image/*"] },
  ];
  const raw = findBucketConfigIssues(buckets).map(normalizeFinding);
  const fixedAt = "2026-08-27T12:00:00.000Z";
  const opts = { project_ref: "ref-stg-01", mode: "audit-active", rawFindings: raw, generated_at: fixedAt };
  const result = assembleResult(opts);
  const { valid, errors } = validate(result, schema);
  assert.equal(valid, true, `schema violations: ${JSON.stringify(errors)}`);
  assert.equal(scanForSecrets(JSON.stringify(result)).length, 0, "secrets leaked in output");
  const json1 = JSON.stringify(assembleResult(opts), null, 2);
  const json2 = JSON.stringify(assembleResult(opts), null, 2);
  assert.equal(json1, json2, "output must be deterministic");
});
