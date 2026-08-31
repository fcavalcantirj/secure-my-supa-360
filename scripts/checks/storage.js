// Storage-objects policy analyzer (pure, DB-free, unit-testable).
//
// Spec entry 11 (coverage-storage): audits the RLS POLICIES on
// `storage.objects` PER BUCKET — not just the `bucket.public` flag. the anon-upload
// anon-upload/delete holes were *policy-level* (a granting INSERT/DELETE policy
// with no path scoping), so bucket.public=true alone missed them.
//
// Mirrors scripts/checks/rls.js + views.js: feed in bucket rows (from
// storage.buckets) + storage.objects policy rows (from pg_policies) + an
// optional async probeFn (an anon-key storage REST probe), get findings out.
// Zero live DB needed in tests — inject probeFn like rls/rpc do.
//
// Inputs (as audit.js will query them):
//   buckets:  [{ id, name, public, file_size_limit, allowed_mime_types, ... }]
//   policies: [{ policyname, cmd, roles:['anon'|...], qual, with_check }]
//            (cmd from pg_policies.cmd: SELECT/INSERT/UPDATE/DELETE/ALL;
//             roles is the parsed role list the policy applies to)
//   probeFn:  async (bucketId) => ProbeResult | null
//            ProbeResult = { list, download, upload, delete, listed, bytes }
//              list     -> HTTP status of GET /storage/v1/object/list/{bucket} (anon key)
//              upload   -> HTTP status of POST /storage/v1/object/{bucket}/<safe-temp>
//              delete   -> HTTP status of DELETE on a non-existent key (404 == authorized)
//              listed   -> # objects returned by the list probe
//              bytes    -> response size of the list probe
//             null = probing disabled (-> confidence stays 'inferred')

import { isSensitiveColumn } from "./pii.js";

// HTTP statuses that mean the action was authorized for anon (not 401/403/42501).
const WRITE_OK = new Set([200, 201, 204]);
const DELETE_OK = new Set([200, 204, 404]); // 404 on a non-existent delete == DELETE was allowed

/** Extract the bucket_id literal(s) referenced in a policy expression.
 *  null  => expression is null/empty/unconstrained (covers ALL buckets).
 *  ['a'] => the literal bucket ids the expression restricts to.
 */
export function extractBucketIds(expr) {
  if (!expr) return null;
  const s = String(expr);
  const ids = new Set();
  const idRe = /bucket_id\s*=\s*'?([A-Za-z0-9_-]+)'?/gi;
  let m;
  while ((m = idRe.exec(s)) !== null) ids.add(m[1]);
  const inRe = /bucket_id\s+in\s*\(([^)]+)\)/gi;
  while ((m = inRe.exec(s)) !== null) {
    for (const lit of String(m[1]).split(",")) {
      const v = lit.trim().replace(/^'|'$/g, "");
      if (v) ids.add(v);
    }
  }
  return ids.size ? [...ids] : null; // no bucket_id ref => covers all buckets
}

function passesBucket(exprSet, bucketId) {
  return exprSet === null || exprSet.includes(bucketId);
}

/** Does a storage.objects policy cover the given bucket? A row must satisfy BOTH
 *  the USING (qual) and WITH CHECK — so bucket scoping is the intersection. */
export function policyCoversBucket(policy, bucketId) {
  const q = extractBucketIds(policy.qual);
  const wc = extractBucketIds(policy.with_check);
  return passesBucket(q, bucketId) && passesBucket(wc, bucketId);
}

/** Normalize the `roles` column of pg_policies (which can arrive as a Postgres
 *  text[] string like "{anon,authenticated}" or an already-parsed array) into a
 *  plain string array. */
export function normalizeRoles(roles) {
  if (!roles) return [];
  if (Array.isArray(roles)) return roles.map(String);
  if (typeof roles === "string") {
    const s = roles.trim();
    if (s === "{}") return [];
    // Postgres text[] renders as "{a,b}"; strip braces + quotes + whitespace
    return s
      .replace(/^\{/, "")
      .replace(/\}$/, "")
      .split(",")
      .map((x) => x.trim().replace(/^["']|["']$/g, ""))
      .filter(Boolean);
  }
  return [];
}

/** Does the policy explicitly apply to the anon / public role? */
export function policyGrantsAnon(policy) {
  const roles = normalizeRoles(policy.roles);
  return roles.includes("anon") || roles.includes("public");
}

/** Does the expression scope to a path/folder (storage.foldername, path_tokens,
 *  or a name LIKE clause) — i.e. tenant-style per-path isolation? */
export function isPathScoped(expr) {
  if (!expr) return false;
  return /storage\.foldername|path_tokens|name\s*(?:il?ke|like)|foldername/i.test(String(expr));
}

export function isSensitiveBucket(name) {
  return isSensitiveColumn(name);
}

// Flat probe for the contract's top-level `probe` field (status, row_count, bytes).
function flatProbe(sp) {
  if (!sp) return null;
  return { status: sp.list ?? null, row_count: sp.listed ?? null, bytes: sp.bytes ?? null };
}

// Full per-operation breakdown for the report (not normalized, survives as evidence).
function storageProbeDetail(sp) {
  if (!sp) return null;
  const { list, download, upload, delete: del, listed, bytes } = sp;
  return { list, download, upload, delete: del, listed, bytes };
}

/** Does a bucket have permissive/null file_size_limit or allowed_mime_types?
 *  `file_size_limit` null/undefined  -> no size cap.
 *  `allowed_mime_types` null/undefined/[]  -> any type accepted.
 *  `allowed_mime_types` containing a wildcard MIME type (e.g. star-star) -> permissive.
 *  Returns { file_size_limit_missing, mime_types_missing, permissive } or null.
 */
export function isBucketMisconfigured(bucket) {
  if (!bucket) return null;
  const issues = { file_size_limit_missing: bucket.file_size_limit == null, mime_types_missing: false, permissive: false };
  if (bucket.allowed_mime_types == null || (Array.isArray(bucket.allowed_mime_types) && bucket.allowed_mime_types.length === 0)) {
    issues.mime_types_missing = true;
  } else if (Array.isArray(bucket.allowed_mime_types)) {
    const hasWildcard = bucket.allowed_mime_types.some((t) => t === "*/*" || t === "*");
    if (hasWildcard) issues.permissive = true;
  }
  const misconfigured = issues.file_size_limit_missing || issues.mime_types_missing || issues.permissive;
  return misconfigured ? issues : null;
}

/** Entry-12 check: find buckets with missing/permissive config (file_size_limit,
 *  allowed_mime_types). Returns finding objects (merge with CHECKS in audit.js). */
export function findBucketConfigIssues(buckets) {
  const findings = [];
  for (const b of buckets) {
    if (!b || !b.id) continue;
    const issues = isBucketMisconfigured(b);
    if (!issues) continue;
    const sensitive = isSensitiveBucket(b.name);
    findings.push({
      check: "storage_bucket_misconfigured",
      category: "coverage-storage",
      severity: b.public && sensitive ? "high" : b.public ? "medium" : "low",
      confidence: "inferred",
      target: `bucket:${b.id}`,
      evidence: {
        bucket_id: b.id,
        bucket_name: b.name,
        public: !!b.public,
        file_size_limit: b.file_size_limit,
        allowed_mime_types: b.allowed_mime_types,
        issues,
        sensitive,
      },
      probe: null,
      fix: {
        sql: [
          `-- Set a file size limit and restrict MIME types for bucket ${b.id}:`,
          `UPDATE storage.buckets SET file_size_limit = 33554432 WHERE id = '${b.id}';`,
          `UPDATE storage.buckets SET allowed_mime_types = ARRAY['image/jpeg','image/png','application/pdf'] WHERE id = '${b.id}';`,
        ],
        rollback_sql: [
          `UPDATE storage.buckets SET file_size_limit = NULL, allowed_mime_types = NULL WHERE id = '${b.id}';`,
        ],
        dashboard_action: "Dashboard -> Storage -> [bucket] -> Settings: set a file size limit and an explicit allowed MIME types list",
        management_api_action: null,
        requires_service_role: false,
      },
    });
  }
  return findings;
}

/** Classify one bucket given all storage.objects policies + a probe result.
 *  Returns 0-N findings (read, insert, tamper, unscoped-path). */
export function classifyBucket(bucket, policies, probe = null) {
  const bid = bucket.id;
  const relevant = policies.filter((p) => policyCoversBucket(p, bid));
  if (relevant.length === 0) return [];

  const anonReadPolicies = relevant.filter((p) => policyGrantsAnon(p) && (p.cmd === "SELECT" || p.cmd === "ALL"));
  const anonSelect = anonReadPolicies.length > 0;
  // An anon-read policy is "unscoped" when its USING has no bucket_id constraint
  // (covers ALL buckets) — a cross-bucket read leak worth flagging even when the
  // bucket itself is non-sensitive.
  const unscopedRead = anonReadPolicies.some((p) => extractBucketIds(p.qual) === null);
  const anonInsert = relevant.some((p) => policyGrantsAnon(p) && (p.cmd === "INSERT" || p.cmd === "ALL"));
  const anonWrite = relevant.some(
    (p) => policyGrantsAnon(p) && (p.cmd === "UPDATE" || p.cmd === "DELETE" || p.cmd === "ALL")
  );
  const unscoped = relevant.some(
    (p) => policyGrantsAnon(p) && !isPathScoped(p.qual) && !isPathScoped(p.with_check)
  );

  const listConfirmed = probe && probe.list === 200 && (probe.listed || 0) > 0;
  const uploadConfirmed = probe && WRITE_OK.has(probe.upload);
  const deleteConfirmed = probe && DELETE_OK.has(probe.delete);
  const sensitive = isSensitiveBucket(bucket.name);

  const findings = [];

  const baseEvidence = {
    bucket_id: bid,
    bucket_name: bucket.name,
    public: !!bucket.public,
    n_policies: relevant.length,
    policy_names: relevant.map((p) => p.policyname),
  };

  const baseFix = {
    sql: [
      `-- Review/revise the anon-granting storage.objects policy for bucket ${bid}:`,
      `-- DROP POLICY IF EXISTS <offending_policy> ON storage.objects;`,
      `-- Re-create scoped + path-gated policies; never grant anon INSERT/UPDATE/DELETE.`,
      `REVOKE SELECT ON storage.objects FROM anon;`,
    ],
    rollback_sql: [
      `GRANT SELECT ON storage.objects TO anon;`,
    ],
    dashboard_action: null,
    management_api_action: null,
    requires_service_role: false,
  };

  // 1. READ leak: anon can SELECT objects. Per spec step 2 we flag SELECT on
  //    sensitive buckets and cross-bucket leaks (an unscoped SELECT policy that
  //    covers ALL buckets). A non-sensitive public bucket's plain read is covered
  //    by the bucket.public check (entry 12), so to avoid double-flagging we do
  //    NOT raise a read finding for a bucket-scoped, non-sensitive SELECT here —
  //    its path-scoping gap still surfaces via storage_policy_unscoped_path above
  //    when the policy lacks a foldername/path guard.
  if (anonSelect && (sensitive || unscopedRead)) {
    let severity = "high";
    const confidence = listConfirmed ? "confirmed" : "inferred";
    if (listConfirmed && sensitive) severity = "critical";
    if (bucket.public && sensitive) severity = "critical";
    findings.push({
      check: "storage_objects_anon_read",
      category: "coverage-storage",
      severity,
      confidence,
      target: `bucket:${bid}`,
      evidence: { ...baseEvidence, ...(probe ? { storage_probe: storageProbeDetail(probe) } : {}) },
      probe: listConfirmed ? flatProbe(probe) : null,
      fix: baseFix,
    });
  }

  // 2. UPLOAD: anon INSERT on storage.objects => arbitrary (anonymous) upload. Critical.
  if (anonInsert) {
    const probeEvidence = unscoped ? { path_scoped: false } : { path_scoped: true };
    findings.push({
      check: "storage_objects_anon_insert",
      category: "coverage-storage",
      severity: "critical",
      confidence: uploadConfirmed ? "confirmed" : "inferred",
      target: `bucket:${bid}`,
      evidence: { ...baseEvidence, ...probeEvidence, ...(probe ? { storage_probe: storageProbeDetail(probe) } : {}) },
      probe: uploadConfirmed ? { status: probe.upload, row_count: 0, bytes: 0 } : null,
      fix: {
        sql: [
          `-- anon INSERT on storage.objects => anyone can upload to bucket ${bid}.`,
          `REVOKE INSERT ON storage.objects FROM anon;`,
          `-- Route uploads through a server-side function or signed-URL upload that`,
          `-- authenticates the caller and validates file type/size/path.`,
        ],
        rollback_sql: [
          `GRANT INSERT ON storage.objects TO anon;`,
        ],
        dashboard_action: null,
        management_api_action: null,
        requires_service_role: false,
      },
    });
  }

  // 3. TAMPER: anon UPDATE/DELETE on storage.objects => tamper or wipe. Critical.
  if (anonWrite) {
    findings.push({
      check: "storage_objects_anon_tamper",
      category: "coverage-storage",
      severity: "critical",
      confidence: deleteConfirmed ? "confirmed" : "inferred",
      target: `bucket:${bid}`,
      evidence: { ...baseEvidence, ...(probe ? { storage_probe: storageProbeDetail(probe) } : {}) },
      probe: deleteConfirmed ? { status: probe.delete, row_count: 0, bytes: 0 } : null,
      fix: {
        sql: [
          `-- anon UPDATE/DELETE on storage.objects => anyone can tamper/wipe bucket ${bid}.`,
          `  REVOKE UPDATE, DELETE ON storage.objects FROM anon;`,
        ],
        rollback_sql: [
          `  GRANT UPDATE ON storage.objects TO anon;`,
          `  GRANT DELETE ON storage.objects TO anon;`,
        ],
        dashboard_action: null,
        management_api_action: null,
        requires_service_role: false,
      },
    });
  }

  // 4. Path scoping: an anon-granting policy with no storage.foldername / path_tokens /
  //    name LIKE guard means the whole bucket is exposed (no per-path tenant isolation).
  if (unscoped) {
    findings.push({
      check: "storage_policy_unscoped_path",
      category: "coverage-storage",
      severity: "medium",
      confidence: "inferred",
      target: `bucket:${bid}`,
      evidence: { ...baseEvidence, anon_grants: ["select", "insert", "update", "delete"].filter(() => true) },
      fix: {
        sql: [
          `-- Add a path/foldername scope to the anon policy so only intended paths are exposed:`,
          `  -- e.g. storage.foldername(name) LIKE 'public/%'`,
          `  -- or remove anon grants entirely and serve via signed URLs.`,
        ],
        rollback_sql: [
          `-- No automated rollback: the path-scope fix is a policy rewrite. Revert the policy DDL manually (restore the original unscoped policy).`,
        ],
        dashboard_action: null,
        management_api_action: null,
        requires_service_role: false,
      },
    });
  }

  return findings;
}

/** Process every bucket: probe each (if probeFn given) and classify.
 *  buckets:  [{ id, name, public, ... }]
 *  policies: [{ policyname, cmd, roles, qual, with_check }]
 *  probeFn:  async (bucketId) => ProbeResult | null
 *  returns:  flat array of finding objects (same shape classifyBucket returns).
 */
export async function processStorage(buckets, policies, probeFn = null) {
  const findings = [];
  for (const b of buckets) {
    if (!b || !b.id) continue;
    let probe = null;
    if (probeFn) {
      try {
        probe = await probeFn(b.id);
      } catch {
        probe = null; // a failed probe must not abort the bucket classification
      }
    }
    for (const f of classifyBucket(b, policies, probe)) {
      findings.push(f);
    }
  }
  return findings;
}
