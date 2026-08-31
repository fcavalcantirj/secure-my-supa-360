// Network & database exposure classifier (pure, DB-free, unit-testable).
//
// Spec entry 18 (coverage-network-db):
//  - Report direct Postgres (5432) reachability, SSL enforcement, network
//    restrictions / IP allowlist state via Management API.
//  - Flag absent network restrictions on a production project.
//  - Report connection pooler mode (transaction vs session) relevant to
//    serverless.
//
// Input: a project config object as returned by
//   GET /v1/projects/{ref}  (and optionally /database for pool_mode).
// Fields consumed: db_ssl, network_restrictions.enabled, pool_mode, name.
// No live API needed in tests — feed mock config objects.

/** Coerce a value that may arrive as a Postgres string ("true"/"false")
 *  or a native boolean into a real boolean. */
function toBool(v) {
  if (typeof v === "boolean") return v;
  if (typeof v === "string") return v.trim().toLowerCase() === "true";
  if (v === 1) return true;
  if (v === 0) return false;
  return false;
}

/** Heuristic: is this a production project? Checks the project name for
 *  common production indicators. Used to gate the "no network restrictions"
 *  finding severity (spec: flag absent restrictions on a production project). */
function isProduction(config) {
  const name = (config && config.name ? String(config.name) : "").toLowerCase();
  return /prod|production|live|prod-|production-/.test(name);
}

/**
 * Classify a project's network + database configuration for exposure.
 *
 * @param {object} config — partial project config from the Management API
 *   { db_ssl, network_restrictions: { enabled, ... }, pool_mode, name }
 * @param {string} [ref="unknown"] — project ref (for management_api_action paths)
 * @returns {Array} contract-shaped raw finding objects
 */
export function classifyNetworkDbConfig(config, ref = "unknown") {
  if (!config || typeof config !== "object") return [];

  // Only proceed if the config contains any relevant field. An empty or
  // unrelated config object means "no data to analyze", not "all insecure".
  const hasAnyField =
    config.network_restrictions !== undefined ||
    config.db_ssl !== undefined ||
    config.pool_mode !== undefined;
  if (!hasAnyField) return [];

  const findings = [];

  // --- 1. Network restrictions / IP allowlist ---
  // When network_restrictions.enabled is false, the Postgres instance is
  // reachable from ANY IP on port 5432 — direct DB exposure.
  const netRestricted = toBool(config.network_restrictions?.enabled);
  if (!netRestricted) {
    const prod = isProduction(config);
    findings.push({
      check: "db_no_network_restrictions",
      category: "coverage-network-db",
      severity: prod ? "high" : "medium",
      confidence: "confirmed",
      target: `project:${ref}`,
      evidence: {
        network_restrictions: config.network_restrictions,
        production: prod,
        postgres_port_open: true,
        reason: "Direct Postgres (5432) reachability is NOT restricted — any IP can connect.",
      },
      fix: {
        sql: [],
        rollback_sql: [],
        dashboard_action: prod
          ? "Dashboard -> Project Settings -> Network: add IP allowlist / restrict to known CIDRs"
          : null,
        management_api_action: {
          method: "PATCH",
          path: `/v1/projects/${ref}/network/restrictions`,
          body: { enabled: true },
        },
        rollback_management_api_action: {
          method: "PATCH",
          path: `/v1/projects/${ref}/network/restrictions`,
          body: { enabled: false },
        },
        requires_service_role: false,
      },
    });
  }

  // --- 2. SSL enforcement ---
  // db_ssl false means Postgres connections are accepted without TLS,
  // allowing MITM on the wire.
  if (!toBool(config.db_ssl)) {
    findings.push({
      check: "db_ssl_disabled",
      category: "coverage-network-db",
      severity: "medium",
      confidence: "confirmed",
      target: `project:${ref}`,
      evidence: {
        db_ssl: config.db_ssl,
        reason: "SSL/TLS is not enforced for Postgres connections — credentials and data traverse the network in cleartext.",
      },
      fix: {
        sql: [],
        rollback_sql: [],
        dashboard_action: "Dashboard -> Project Settings -> Network: enable 'Enforce SSL'",
        management_api_action: {
          method: "PATCH",
          path: `/v1/projects/${ref}/network/restrictions`,
          body: { db_ssl: true },
        },
        rollback_management_api_action: {
          method: "PATCH",
          path: `/v1/projects/${ref}/network/restrictions`,
          body: { db_ssl: false },
        },
        requires_service_role: false,
      },
    });
  }

  // --- 3. Connection pooler mode ---
  // "session" pool mode does not work well with serverless (functions that
  // scale to zero), causing connection exhaustion. "transaction" is the
  // recommended mode.
  const poolMode = config.pool_mode;
  if (poolMode === "session" || poolMode === "Session") {
    findings.push({
      check: "db_pool_session_mode",
      category: "coverage-network-db",
      severity: "low",
      confidence: "confirmed",
      target: `project:${ref}`,
      evidence: {
        pool_mode: poolMode,
        reason: "Connection pooler is in 'session' mode, which is incompatible with serverless (functions scale to zero, exhaust connection limits). Use 'transaction' mode.",
      },
      fix: {
        sql: [],
        rollback_sql: [],
        dashboard_action: "Dashboard -> Project Settings -> Connection Pooler: switch pool mode to 'Transaction'",
        management_api_action: {
          method: "PATCH",
          path: `/v1/projects/${ref}/database`,
          body: { pool_mode: "transaction" },
        },
        rollback_management_api_action: {
          method: "PATCH",
          path: `/v1/projects/${ref}/database`,
          body: { pool_mode: "session" },
        },
        requires_service_role: false,
      },
    });
  }

  return findings;
}

/**
 * Process a project config into findings.
 * Thin wrapper around classifyNetworkDbConfig for audit.js wiring symmetry.
 */
export function processNetworkDb(config, ref) {
  return classifyNetworkDbConfig(config, ref);
}

export { toBool, isProduction };
