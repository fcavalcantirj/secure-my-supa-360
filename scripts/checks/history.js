// Historical exposure detection (WO-9 — flagship capability).
//
// Every competing auditor answers "are you exposed?". None answers
// "were you exposed, and did anyone actually take the data?".
// pg_stat_statements records REAL query execution history — including
// anon-key queries where rows > 0 (proving data was returned, not just attempted).
//
// PURE module (no DB, no network): consumes pg_stat_statements rows from audit.js
// and classifies them into findings.

// Patterns that indicate sensitive data in query text (for redaction).
const SENSITIVE_PATTERNS = [
  /\b\d{11}\b/g,        // CPF (11-digit numbers)
  /\b\d{14}\b/g,        // CNPJ (14-digit numbers)
  /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g, // email addresses
  /\b\d{6,}\b/g,        // long digit runs (>6 digits — likely IDs/tokens)
];

// Tag used to mark our own audit SQL queries so they can be excluded
// from historical analysis (they are not attacker activity).
const PROBE_TAG = "/* supa360-probe */";

// Known PostgREST-internal function-call table references that are not
// real user tables and should never be classified as data access.
const KNOWN_INTERNAL_TABLES = new Set([
  "json_to_record", "json_populate_record", "json_to_recordset",
  "json_populate_recordset", "pg_table_def", "unnest",
  "generate_series", "generate_subscripts", "xmltable",
]);

// Known PostgREST-internal CTE alias names that appear as table references
// in pg_stat_statements but are NOT real user tables (e.g. pgrst_source, _POSTGREST_T).
const CTE_ALIAS_PREFIXES = new Set([
  "pgrst_source", "pgrst_query", "pgrst_insert", "pgrst_update",
  "pgrst_delete", "pgrst_embed", "_postgrest_t", "_postg_rest_t",
  "_rq", "_r", "_rr", "_q",
]);

/** Redact sensitive literal values from a query string.
 *  pg_stat_statements normalizes values to $1/$2, but defensive redaction
 *  catches any literal CPF/email/long-digit patterns that might appear. */
export function redactQuery(query) {
  if (!query) return null;
  let redacted = String(query);
  for (const pattern of SENSITIVE_PATTERNS) {
    redacted = redacted.replace(pattern, "[REDACTED]");
  }
  return redacted;
}

/** Does a query look like an enumeration (bulk hoover) rather than a
 *  per-key lookup?
 *
 *  A bulk enumeration is a SELECT with LIMIT/OFFSET that does NOT have a
 *  meaningful WHERE clause — i.e., it scans the whole table without a
 *  row-level filter. Per-key lookups (WHERE col = $1) are NOT enumeration.
 *
 *  Edge cases handled:
 *  - Tautological WHEREs (WHERE true, WHERE 1=1) are treated as no filter.
 *  - WHERE inside CTE wrappers is still detected.
 */
export function isEnumeration(query) {
  if (!query) return false;
  const q = query.replace(/\s+/g, " ").trim().toUpperCase();

  // Must have LIMIT or OFFSET (bulk scanning pattern).
  if (!/\b(?:LIMIT|OFFSET)\b/.test(q)) return false;

  // Must involve SELECT (enumeration scanning is read-side only).
  if (!/\bSELECT\b/.test(q)) return false;

  // No WHERE at all → enumeration.
  if (!/\bWHERE\b/.test(q)) return true;

  // WHERE exists — check whether it is a tautology (WHERE true, WHERE 1=1, etc.)
  // that does not actually filter anything.
  const whereIdx = q.indexOf("WHERE");
  const afterWhere = q.slice(whereIdx + 5).trim();
  // Extract the WHERE condition (up to the next clause keyword or end of string).
  const endMatch = afterWhere.match(/^(.+?)(?:\s+LIMIT|\s+OFFSET|\s+ORDER\s+BY|\s+GROUP\s+BY|\s+HAVING|\s+UNION|\s+;|$)/);
  const whereClause = (endMatch ? endMatch[1] : afterWhere).trim();

  // Tautological WHEREs (optionally parenthesized) → still enumeration.
  if (/^(?:\(?)TRUE(?:\)?)$/.test(whereClause)) return true;
  if (/^(?:\(?)FALSE(?:\)?)$/.test(whereClause)) return true;
  if (/^(?:\(?)1\s*=\s*1(?:\)?)$/.test(whereClause)) return true;
  if (/^(?:\(?)0\s*=\s*0(?:\)?)$/.test(whereClause)) return true;

  // Has a meaningful WHERE → not enumeration.
  return false;
}

/** Parse a SQL table reference token into its name and optional schema.
 *
 *  Handles PostgREST-qualified names:
 *    "public"."patient_photos"  →  { name: "patient_photos", schema: "public" }
 *    public.patient_photos      →  { name: "patient_photos", schema: "public" }
 *    "patient_photos"           →  { name: "patient_photos", schema: undefined }
 *    patient_photos             →  { name: "patient_photos", schema: undefined }
 *
 *  @param {string} ref - the raw table reference token (without keyword)
 *  @returns {{name: string, schema?: string}|null} parsed ref, or null
 */
function extractTableFromRef(ref) {
  if (!ref) return null;
  // "schema"."table" → { name, schema }
  let m = ref.match(/^"([^"]+)"\s*\.\s*"([^"]+)"$/);
  if (m) return { name: m[2], schema: m[1] };
  // schema.table → { name, schema }
  m = ref.match(/^(\w+)\s*\.\s*(\w+)$/);
  if (m) return { name: m[2], schema: m[1] };
  // "table" → { name }
  m = ref.match(/^"([^"]+)"$/);
  if (m) return { name: m[1] };
  // plain name
  m = ref.match(/^(\w+)$/);
  if (m) return { name: m[1] };
  return null;
}

/** Extract all user-table references after FROM/INTO/UPDATE keywords.
 *
 *  Skips subqueries (parenthesised), system catalogs (pg_*, information_schema),
 *  and known PostgREST-internal function calls (json_to_record, unnest, etc.).
 *
 *  @param {string} query - the SQL query text
 *  @returns {Array<{name: string, schema?: string}>} parsed table refs (deduplicated)
 */
export function extractTableNames(query) {
  if (!query) return [];
  const q = query.replace(/\s+/g, " ").trim();
  const tables = [];

  // Match keywords followed by a table reference.
  const kwRe = /\b(FROM|INTO|UPDATE)\s+/gi;
  let m;
  while ((m = kwRe.exec(q)) !== null) {
    const rest = q.slice(kwRe.lastIndex).trim();
    // Skip subqueries: reference starts with (
    if (rest[0] === "(") continue;

    // Match the table reference token: "schema"."table" / schema.table / "table" / table
    const refMatch = rest.match(/^("(?:[^"]+"\s*\.\s*)?"[^"]+"|[^\s,();]+)/);
    if (!refMatch) continue;

    const ref = refMatch[1].trim();
    const parsed = extractTableFromRef(ref);
    if (!parsed) continue;

    // Skip system catalogs and known internal function calls.
    // Check the full reference (includes schema — e.g. information_schema.columns
    // would otherwise lose its schema and extract to just "columns").
    // Also filter CTE aliases (e.g. pgrst_source, _POSTGREST_T) — they are
    // PostgREST internal wrappers, not real user tables.
    const refBare = ref.replace(/"/g, "").toLowerCase();
    if (refBare.startsWith("pg_")) continue;
    if (refBare.startsWith("information_schema.")) continue;
    if (parsed.name.toLowerCase().startsWith("pg_")) continue;
    if (KNOWN_INTERNAL_TABLES.has(parsed.name.toLowerCase())) continue;
    if (CTE_ALIAS_PREFIXES.has(parsed.name.toLowerCase())) continue;

    tables.push(parsed);
  }

  // Deduplicate by name+schema
  const seen = new Set();
  return tables.filter((t) => {
    const key = `${t.schema || ""}.${t.name}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

/** Extract the primary table name from a SQL query.
 *  Returns the first user-table referenced after FROM/INTO/UPDATE,
 *  preferring one that matches the scanned table list.
 *
 *  @param {string} query - the SQL query text
 *  @param {string[]} [tableNames=[]] - known table names for preference matching
 *  @returns {string|null} the table name, or null if none found
 */
export function extractTableName(query, tableNames = []) {
  const tables = extractTableNames(query);
  if (tables.length === 0) return null;
  // Prefer a table that matches the current schema scan (avoids CTE aliases
  // or subquery tables being picked over the real target table).
  const matched = tables.find((t) => tableNames.includes(t.name));
  return matched ? matched.name : tables[0].name;
}

/** Check if a query is one of our own audit probes.
 *
 *  Two detection paths:
 *  1. Tagged probes: the sql() call in audit.js that fetches pg_stat_statements
 *     data is prefixed with `/* supa360-probe *​/`. Those queries are excluded.
 *  2. Legacy unmarked probes: the HTTP-based table probes (probeAnonAccess with
 *     ?limit=1) generate simple SQL that PostgREST executes as anon — these have
 *     no tag but share a characteristic shape: SELECT * FROM "schema"."table"
 *     LIMIT 1 with no WHERE clause.
 */
export function isProbeQuery(query) {
  if (!query) return false;
  const q = String(query);

  // Tagged probe (sql() calls in audit.js prefixed with the comment).
  if (q.includes(PROBE_TAG)) return true;

  // Legacy unmarked probe shapes — only OUR distinctive shapes, never generic
  // patterns that could match attacker reconnaissance. A bare "SELECT count(*)
  // FROM table" is textbook table sizing by an attacker — do NOT suppress it.
  // Only match our specific probe aliases (anon_visible_*, authed_visible_*)
  // and our accessibility probe shape ($1 AS test, count(*)::text).

  // 1. SELECT * FROM table LIMIT 1 with no WHERE (probeAnonAccess ?limit=1).
  if (
    /^SELECT\s+\*\s+FROM\b/i.test(q) &&
    /\bLIMIT\s+1\b/i.test(q) &&
    !/\bWHERE\b/i.test(q)
  ) {
    return true;
  }

  // 2. Accessibility probe: SELECT $1 AS test, count(*)::text AS result FROM table
  //    WHERE-agnostic — our probe adds a WHERE for some tables (e.g. bucket_id).
  if (
    /^SELECT\s+\$1\s+AS\s+test/i.test(q) &&
    /\bcount\s*\(\s*\*\s*\)\s*::text\b/i.test(q)
  ) {
    return true;
  }

  // 3. Visibility probes: SELECT count(*) AS anon_visible_* / authed_visible_* FROM table
  //    These aliases are emitted ONLY by our probe logic — nobody else uses them.
  if (/\bcount\s*\(\s*\*\s*\)\s+AS\s+(?:anon|authed)_visible_/i.test(q)) {
    return true;
  }

  return false;
}

/** Check if a query is a PostgREST internal / infrastructure statement that
 *  does not represent real data access by an application user.
 *
 *  - set_config('role', ...), obj_description(...), etc. — no FROM/INTO/UPDATE
 *  - Queries referencing only system catalogs (pg_*, information_schema)
 *  - Function-call references like json_to_record(...)
 */
export function isInternalQuery(query) {
  if (!query) return false;
  const q = query.replace(/\s+/g, " ").trim();

  // Known PostgREST-internal function calls.
  if (/\bSET_CONFIG\b/i.test(q)) return true;
  if (/\bOBJ_DESCRIPTION\b/i.test(q)) return true;

  // No FROM / INTO / UPDATE → no real relation referenced → internal.
  if (!/\b(FROM|INTO|UPDATE)\b/i.test(q)) return true;

  // If all extracted tables are system catalogs or internal functions → internal.
  const tables = extractTableNames(q);
  if (tables.length === 0) return true;

  return false;
}

/** Map SQL verb to access type.
 *
 *  PostgREST wraps EVERY operation in a CTE: the real verb (DELETE, INSERT, etc.)
 *  appears INSIDE the CTE body, while the outer wrapper is always SELECT.
 *  e.g.  WITH pgrst_source AS (DELETE FROM "public"."t" WHERE ...) SELECT * FROM pgrst_source
 *
 *  So we cannot rely on the CTE→main-query boundary. Instead, we scan the
 *  ENTIRE statement for the operation keyword associated with a table
 *  reference (DELETE FROM, INSERT INTO, UPDATE <table>, MERGE INTO), giving
 *  write verbs priority over SELECT.
 */
function sqlVerb(query) {
  if (!query) return "UNKNOWN";
  const q = query.replace(/\s+/g, " ").trim().toUpperCase();

  // Check write operations first — they are more specific than SELECT and
  // may appear inside CTEs (PostgREST wraps all verbs in pgrst_source CTE).
  if (/\bDELETE\s+FROM\b/.test(q)) return "DELETE";
  if (/\bINSERT\s+INTO\b/.test(q)) return "INSERT";
  if (/\bMERGE\s+INTO\b/.test(q)) return "MERGE";
  // UPDATE is tricky — "UPDATE" can appear in column values or string literals.
  // Match UPDATE followed by a table reference (quoted or unquoted).
  if (/\bUPDATE\s+("?"[^"]+"?"\.?|"?[\w]+)"?\.?"?\w+\s+(SET|WHERE)/.test(q)) return "UPDATE";
  // Fallback: UPDATE keyword followed by a table-name-like token
  if (/\bUPDATE\s+("([^"]+)"\.?"([^"]+)"|(\w+)\.(\w+)|"([^"]+)"|(\w+))\s/.test(q)) return "UPDATE";

  if (/\bSELECT\b/.test(q)) return "SELECT";
  return "OTHER";
}

/** Extract per-row properties from a pg_stat_statements row.
 *  Applies probe/internal filtering and table-name extraction.
 *  Returns a properties object or null if the row should be skipped.
 */
function extractRowProperties(row, tableNames = [], tableSchemas = {}) {
  if (!row || !row.query) return null;

  // Filter out our own audit probes (tagged or legacy unmarked shapes).
  if (isProbeQuery(row.query)) return null;

  // Filter out PostgREST internals (set_config, obj_description, etc.).
  if (isInternalQuery(row.query)) return null;

  const verb = sqlVerb(row.query);
  if (verb === "UNKNOWN" || verb === "OTHER") return null;

  const calls = row.calls || 0;
  const rows = row.rows || 0;
  if (rows === 0) return null; // Executed but returned no data → not a leak.

  const role = row.rolname || "unknown";
  const since = row.stats_since || null;

  // Extract table name + schema, handling PostgREST "schema"."table" qualified names.
  const tables = extractTableNames(row.query);
  if (tables.length === 0) return null;
  // Prefer a table that matches the current schema scan (avoids CTE aliases
  // or subquery tables being picked over the real target table).
  const matched = tables.find((t) => tableNames.includes(t.name));
  const tableInfo = matched || tables[0];
  const tableName = tableInfo.name;

  // Resolve schema: use the schema from the query if present, otherwise
  // look it up from the scanned relation list (tableSchemas). This merges
  // bare "objects" references with qualified "storage.objects" ones.
  // If unresolvable, schema stays undefined — group by bare name.
  let tableSchema = tableInfo.schema;
  if (!tableSchema && tableSchemas[tableName]) {
    tableSchema = tableSchemas[tableName];
  }

  const tableHasData = tableNames.includes(tableName);
  const enumeration = isEnumeration(row.query);
  const redacted = redactQuery(row.query);

  return {
    role,
    table: tableName,
    schema: tableSchema,
    verb,
    calls,
    rows,
    enumeration,
    enumerationCalls: enumeration ? calls : 0,
    enumerationRows: enumeration ? rows : 0,
    lookupCalls: enumeration ? 0 : calls,
    tableHasData,
    query: redacted.slice(0, 200),
    stats_since: since,
  };
}

/** Classify a set of row properties into a finding object.
 *  Used both for single-row classification (classifyHistoricalAccess) and
 *  for aggregated groups (processHistoricalAccess).
 */
function classifyProperties(props) {
  const { role, table, schema, verb, calls, rows, enumeration, enumerationCalls, enumerationRows, lookupCalls, tableHasData, query, stats_since } = props;

  // WO-18: role label for human-readable output (never hardcode "anon").
  const roleLabel = (role || "anon").charAt(0).toUpperCase() + (role || "anon").slice(1);
  const rolePrefix = role || "anon";

  const isWrite = verb === "INSERT" || verb === "UPDATE" || verb === "DELETE" || verb === "MERGE";
  const isRead = verb === "SELECT";

  // Schema-qualified table name for the target (e.g. "public.patient_photos").
  const qualifiedTable = schema ? `${schema}.${table}` : table;

  let severity, check, reason;

  if (enumeration && isRead) {
    // LIMIT/OFFSET without WHERE = bulk enumeration.
    // WO-18: report enumeration-specific counts (WHERE-less), not the group total.
    // The group may contain 9400 per-key lookups + 37 WHERE-less scans; only
    // the 37 are enumeration. Keep group totals in a separate evidence field.
    severity = tableHasData ? "critical" : "high";
    check = `${rolePrefix}_historical_enumeration`;
    reason = `${roleLabel} bulk enumeration (${enumerationCalls || 0} WHERE-less call(s), ${enumerationRows || 0} row(s) returned) — LIMIT/OFFSET without WHERE hoovered ${qualifiedTable}. Group total: ${calls} call(s), ${rows} row(s) (${lookupCalls || 0} per-key lookups). Evidence access already occurred; preserve pg_stat_statements for audit trail.`;
  } else if (isWrite) {
    severity = "high";
    check = `${rolePrefix}_historical_write`;
    reason = `${roleLabel} ${verb} wrote ${rows} row(s) across ${calls} call(s) on ${qualifiedTable} via the Data API.`;
  } else if (isRead && tableHasData) {
    // Confirmed read of a table that currently holds data -> CRITICAL
    severity = "critical";
    check = `${rolePrefix}_historical_read_critical`;
    reason = `CONFIRMED: ${roleLabel} SELECT returned ${rows} row(s) across ${calls} call(s) from ${qualifiedTable} (currently holds data). Evidence access already occurred — preserve pg_stat_statements for breach-notification assessment (potential GDPR/LGPD event).`;
  } else if (isRead) {
    severity = "high";
    check = `${rolePrefix}_historical_read`;
    reason = `${roleLabel} SELECT returned ${rows} row(s) across ${calls} call(s) from ${qualifiedTable}.`;
  } else {
    severity = "high";
    check = `${rolePrefix}_historical_access`;
    reason = `${roleLabel} ${verb} returned ${rows} row(s) across ${calls} call(s).`;
  }

  return {
    check,
    category: "coverage-history",
    severity,
    confidence: "confirmed",
    target: `table:${qualifiedTable}:role:${role}:verb:${verb}`,
    evidence: {
      role,
      table_name: table,
      schema: schema || null,
      qualified_table: qualifiedTable,
      verb,
      calls,
      rows,
      enumeration,
      enumeration_calls: enumerationCalls || 0,
      enumeration_rows: enumerationRows || 0,
      lookup_calls: lookupCalls || 0,
      table_has_data: tableHasData,
      query,
      stats_since,
    },
    fix: {
      sql: [],
      rollback_sql: [],
      dashboard_action: "Revoke anon/authenticated SELECT/INSERT/UPDATE/DELETE grants on this table. Audit pg_stat_statements for this query pattern and preserve evidence for breach-notification assessment.",
      management_api_action: null,
      requires_service_role: false,
    },
    references: [
      "https://supabase.com/docs/guides/api",
      "https://wiki.postgresql.org/wiki/Pg_stat_statements",
    ],
    title: classificationTitle(verb, qualifiedTable, enumeration, role),
    explain: reason,
  };
}

/** Build a human-readable title for a classification.
 *  WO-18: branches on role so an authenticated row is never labelled "anon". */
function classificationTitle(verb, table, enumeration, role) {
  const roleLabel = (role || "anon").charAt(0).toUpperCase() + (role || "anon").slice(1);
  if (enumeration && verb === "SELECT") {
    return `Historical ${roleLabel} enumeration of ${table}`;
  }
  return `Historical ${roleLabel} ${verb} of ${table}`;
}

/** Classify a single pg_stat_statements row into a finding (or null).
 *  row: { rolname, query, calls, rows, stats_since }
 *  tableNames: array of current table names (for PII escalation check)
 *  Returns a finding object or null (if the row is a probe, internal, or has no data). */
export function classifyHistoricalAccess(row, tableNames = [], tableSchemas = {}) {
  const props = extractRowProperties(row, tableNames, tableSchemas);
  if (!props) return null;
  return classifyProperties(props);
}

/** Process pg_stat_statements rows into aggregated findings.
 *
 *  1. Filters out audit probes and PostgREST internals.
 *  2. Groups remaining rows by (role, schema.table, verb).
 *  3. Aggregates calls/rows/enumeration_calls per group and emits ONE finding per group.
 *
 *  rows: array of { rolname, query, calls, rows, stats_since }
 *  tableNames: array of current table names (for PII escalation check)
 *  tableSchemas: map of table_name -> schema_name (for bare-name resolution)
 *  Returns { findings, history_available, stats_since, note, excluded_count } */
export function processHistoricalAccess(rows, tableNames = [], tableSchemas = {}) {
  if (!rows || rows.length === 0) {
    return {
      findings: [],
      history_available: false,
      stats_since: null,
      excluded_count: 0,
      note: "pg_stat_statements extension not present, or stats were RESET. Historical access cannot be determined — do NOT interpret as clean.",
    };
  }

  let earliestSince = null;
  const properties = [];
  let excludedCount = 0;

  for (const row of rows) {
    if (row.stats_since && (!earliestSince || row.stats_since < earliestSince)) {
      earliestSince = row.stats_since;
    }
    const props = extractRowProperties(row, tableNames, tableSchemas);
    if (props) properties.push(props);
    else excludedCount++;
  }

  if (properties.length === 0) {
    return {
      findings: [],
      history_available: true,
      stats_since: earliestSince,
      excluded_count: excludedCount,
      note: "pg_stat_statements history available — all entries were audit probes, PostgREST internals, or returned no rows.",
    };
  }

  // --- Aggregate by (role, schema.table, verb) ---------------------------------
  const groups = new Map();
  for (const props of properties) {
    const qualifiedTable = props.schema ? `${props.schema}.${props.table}` : props.table;
    const key = `${props.role}|${qualifiedTable}|${props.verb}`;
    if (!groups.has(key)) {
      groups.set(key, {
        role: props.role,
        table: props.table,
        schema: props.schema,
        verb: props.verb,
        calls: 0,
        rows: 0,
        hasEnumeration: false,
        enumerationCalls: 0,
        enumerationRows: 0,
        lookupCalls: 0,
        tableHasData: false,
        sampleQuery: props.query,
        stats_since: props.stats_since,
        queryCount: 0,
      });
    }
    const g = groups.get(key);
    g.calls += props.calls;
    g.rows += props.rows;
    g.hasEnumeration = g.hasEnumeration || props.enumeration;
    if (props.enumeration) { g.enumerationCalls += props.calls; g.enumerationRows += props.rows; }
    else g.lookupCalls += props.calls;
    g.tableHasData = g.tableHasData || props.tableHasData;
    g.queryCount += 1;
    if (props.stats_since && (!g.stats_since || props.stats_since < g.stats_since)) {
      g.stats_since = props.stats_since;
    }
  }

  // --- Classify each group ----------------------------------------------
  const findings = [];
  for (const g of groups.values()) {
    const props = {
      role: g.role,
      table: g.table,
      schema: g.schema,
      verb: g.verb,
      calls: g.calls,
      rows: g.rows,
      enumeration: g.hasEnumeration,
      enumerationCalls: g.enumerationCalls,
      enumerationRows: g.enumerationRows,
      lookupCalls: g.lookupCalls,
      tableHasData: g.tableHasData,
      query: g.sampleQuery,
      stats_since: g.stats_since,
    };
    const finding = classifyProperties(props);
    finding.evidence.query_count = g.queryCount;
    finding.evidence.enumeration_calls = g.enumerationCalls;
    finding.evidence.enumeration_rows = g.enumerationRows;
    finding.evidence.lookup_calls = g.lookupCalls;
    findings.push(finding);
  }

  return {
    findings,
    history_available: true,
    stats_since: earliestSince,
    excluded_count: excludedCount,
    note: null,
  };
}
