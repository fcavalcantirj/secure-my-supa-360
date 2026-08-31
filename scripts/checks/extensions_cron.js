// Extensions, pg_cron, pg_net, and Vault exposure classifier (pure, DB-free).
//
// Spec entry 19 (coverage-extensions-cron):
//  - List installed extensions and versions; flag risky ones (http, pg_net)
//    reachable by low-priv roles and any with known-CVE versions.
//  - Enumerate pg_cron jobs; flag jobs issuing net.http_post with embedded
//    secrets in the command.
//  - Check vault.decrypted_secrets access grants; flag anon/authenticated
//    readability.
//
// Input: data from SQL queries run by audit.js:
//   extensions:  [{ extname, extversion }]
//   cronJobs:    [{ jobid, schedule, command, database, username }]
//   vaultGrants: { anon_select: bool, auth_select: bool } | null (if vault not installed)
//
// Zero live DB needed in tests — feed mock data arrays.

// Extensions that allow outbound HTTP / network from the DB (SSRF +
// data-exfiltration surface). If installed, anon/auth-executable functions
// from these extensions let callers pivot to internal services.
const RISKY_EXTENSIONS = new Set(["http", "pg_net"]);

// Minimal known-vulnerable version registry. Each entry maps an extension name
// to a set of version strings known to have CVEs. This is a small curated set
// — a real deployment would extend this from a vulnerability database.
const KNOWN_VULNERABLE = new Map([
  ["pg_net", new Set(["0.0.1", "0.0.2", "0.0.3", "0.0.4", "0.0.5", "0.0.6"])],
  ["http", new Set(["1.1", "1.0"])],
]);

// Patterns for detecting secrets embedded in cron job commands.
// These are intentionally broad to catch secrets in any position.
const COMMAND_SECRET_PATTERNS = [
  {
    name: "bearer_token",
    regex: /bearer\s+eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}/i,
  },
  {
    name: "supabase_pat",
    regex: /sbp_[a-zA-Z0-9_]{20,}/i,
  },
  {
    name: "supabase_secret",
    regex: /supabase_secret_[a-zA-Z0-9_]{20,}/i,
  },
  {
    name: "db_connstring",
    regex: /postgres(?:ql)?:\/\/[^:\s]+:[^@\s]+@/i,
  },
  {
    name: "generic_api_key",
    regex: /(?:api[_-]?key|secret|token)\s*[:=]\s*[a-zA-Z0-9_]{16,}/i,
  },
];

// Regex for detecting net.http_post / http_post calls (outbound HTTP from cron).
const HTTP_CALL_IN_COMMAND = /\b(net\.http_post|http_post|http_get|net\.http_get)\b/i;

/** Redact detected secret patterns from a string, replacing with [REDACTED]. */
export function redactSecrets(text) {
  if (!text || typeof text !== "string") return text || "";
  let redacted = text;
  for (const { regex } of COMMAND_SECRET_PATTERNS) {
    const re = new RegExp(regex.source, regex.flags);
    redacted = redacted.replace(re, "[REDACTED]");
  }
  // Also redact Supabase PATs and JWTs not caught above
  redacted = redacted.replace(/sbp_[a-zA-Z0-9_]{20,}/gi, "sbp_[REDACTED]");
  redacted = redacted.replace(
    /eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}/g,
    "eyJ...[REDACTED]"
  );
  return redacted;
}

/** Coerce a value to boolean (handles "true"/"false" strings from PG). */
function toBool(v) {
  if (typeof v === "boolean") return v;
  if (typeof v === "string") return v.trim().toLowerCase() === "true";
  return Boolean(v);
}

/**
 * Check if an extension name is in the risky set.
 */
export function isRiskyExtension(extname) {
  return RISKY_EXTENSIONS.has(extname);
}

/**
 * Check if an extension version is in the known-vulnerable registry.
 * @returns {string|null} — the CVE category or null
 */
export function getVulnerableVersion(extname, extversion) {
  if (!extname || !extversion) return null;
  const vuln = KNOWN_VULNERABLE.get(extname);
  if (vuln && vuln.has(extversion)) return `known-vulnerable:${extname}:${extversion}`;
  return null;
}

/**
 * Scan a cron job command string for embedded secrets.
 * @returns {Array<{name, match}>} — list of detected secret patterns
 */
export function scanCronCommandForSecrets(command) {
  if (!command || typeof command !== "string") return [];
  const found = [];
  for (const { name, regex } of COMMAND_SECRET_PATTERNS) {
    const re = new RegExp(regex.source, regex.flags);
    const m = re.exec(command);
    if (m) {
      found.push({ name, match: m[0].slice(0, 8) + "..." });
    }
  }
  return found;
}

/**
 * Classify a single installed extension.
 * @returns {Array} finding objects (0, 1, or 2)
 */
export function classifyExtension(ext) {
  if (!ext || !ext.extname) return [];
  const findings = [];
  const { extname, extversion } = ext;

  // 1. Risky extension (http, pg_net) installed
  if (isRiskyExtension(extname)) {
    findings.push({
      check: "extension_risky_installed",
      category: "coverage-extensions-cron",
      severity: "medium",
      confidence: "confirmed",
      target: `extension:${extname}`,
      evidence: {
        extname,
        extversion,
        risk: "allows outbound HTTP/network from DB (SSRF, data exfiltration)",
        reachable_by_low_priv: true,
      },
      fix: {
        sql: [`DROP EXTENSION IF EXISTS ${extname};`],
        rollback_sql: [`CREATE EXTENSION IF NOT EXISTS ${extname};`],
        dashboard_action: null,
        management_api_action: null,
        requires_service_role: false,
      },
    });
  }

  // 2. Known-vulnerable version
  const vulnId = getVulnerableVersion(extname, extversion);
  if (vulnId) {
    findings.push({
      check: "extension_known_vulnerable",
      category: "coverage-extensions-cron",
      severity: "high",
      confidence: "confirmed",
      target: `extension:${extname}`,
      evidence: {
        extname,
        extversion,
        cve: vulnId,
      },
      fix: {
        sql: [`ALTER EXTENSION ${extname} UPDATE VERSION;`],
        rollback_sql: [`-- Rollback: downgrading an extension requires a specific version.`, `ALTER EXTENSION ${extname} UPDATE TO '${ext.extversion}';`],
        dashboard_action: null,
        management_api_action: null,
        requires_service_role: false,
      },
    });
  }

  return findings;
}

/**
 * Classify a single pg_cron job.
 * @returns {Array} finding objects (0 or 1)
 */
export function classifyCronJob(job) {
  if (!job || job.jobid === undefined) return [];
  const findings = [];
  const { jobid, schedule, command, database, username } = job;

  // Flag jobs that use net.http_post with embedded secrets
  const secrets = scanCronCommandForSecrets(command);
  const usesHttp = HTTP_CALL_IN_COMMAND.test(command || "");

  if (secrets.length > 0) {
    findings.push({
      check: "cron_job_embedded_secret",
      category: "coverage-extensions-cron",
      severity: "high",
      confidence: "confirmed",
      target: `cron:${jobid}`,
      evidence: {
        jobid,
        schedule,
        database,
        username,
        uses_http_post: usesHttp,
        secrets_found: secrets,
        command_preview: redactSecrets(command || "").slice(0, 200),
      },
      fix: {
        sql: [
          `-- Remove the secret from the cron job command and use vault.get_secret() instead:`,
          `UPDATE cron.job SET command = replace(command, '<secret-value>', vault.get_secret('api_key')) WHERE jobid = ${jobid};`,
          `-- Or delete the job if the secret cannot be removed:`,
          `SELECT cron.unschedule(${jobid});`,
        ],
        rollback_sql: [
          `-- Rollback: the original command (with secret) is not retained for safety.`,
          `-- Reschedule the job manually with cron.schedule() or restore from a pre-fix snapshot.`,
        ],
        dashboard_action: null,
        management_api_action: null,
        requires_service_role: false,
      },
    });
  }

  return findings;
}

/**
 * Classify vault.decrypted_secrets access grants.
 * @returns {Array} finding objects (0 or 1)
 */
export function classifyVaultGrants(vaultGrants, ref = "unknown") {
  if (!vaultGrants || typeof vaultGrants !== "object") return [];

  const anonRead = toBool(vaultGrants.anon_select);
  const authRead = toBool(vaultGrants.auth_select);

  if (!anonRead && !authRead) return [];

  return [
    {
      check: "vault_decrypted_secrets_exposed",
      category: "coverage-extensions-cron",
      severity: "critical",
      confidence: "confirmed",
      target: `project:${ref}`,
      evidence: {
        table: "vault.decrypted_secrets",
        anon_select: anonRead,
        auth_select: authRead,
      },
      fix: {
        sql: [
          ...(anonRead ? [`REVOKE SELECT ON TABLE vault.decrypted_secrets FROM anon;`] : []),
          ...(authRead ? [`REVOKE SELECT ON TABLE vault.decrypted_secrets FROM authenticated;`] : []),
        ],
        rollback_sql: [
          ...(anonRead ? [`GRANT SELECT ON TABLE vault.decrypted_secrets TO anon;`] : []),
          ...(authRead ? [`GRANT SELECT ON TABLE vault.decrypted_secrets TO authenticated;`] : []),
        ],
        dashboard_action: null,
        management_api_action: null,
        requires_service_role: false,
      },
    },
  ];
}

/**
 * Process all extensions + cron jobs + vault grants into findings.
 * @param {object} data — { extensions: [], cronJobs: [], vaultGrants: {} | null }
 * @param {string} ref — project ref
 */
export function processExtensionsCron(data = {}, ref = "unknown") {
  const findings = [];

  if (data.extensions && Array.isArray(data.extensions)) {
    for (const ext of data.extensions) {
      for (const f of classifyExtension(ext)) findings.push(f);
    }
  }

  if (data.cronJobs && Array.isArray(data.cronJobs)) {
    for (const job of data.cronJobs) {
      for (const f of classifyCronJob(job)) findings.push(f);
    }
  }

  if (data.vaultGrants) {
    for (const f of classifyVaultGrants(data.vaultGrants, ref)) findings.push(f);
  }

  return findings;
}

export { toBool };
