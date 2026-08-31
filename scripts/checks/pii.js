// PII / sensitive-data classifier (pure, DB-free, no deps).
//
// Spec entry 15 (coverage-auth: PII classifier to calibrate severity):
//  - Classify columns by name/type heuristics: cpf, cnpj, email, phone,
//    birthdate, health/medical, address, government id, credentials.
//  - Any CONFIRMED anon/authenticated leak of a sensitive column escalates
//    to critical severity.
//  - Record classification in finding.evidence for report + breach context.
//
// Shared across check modules (rls.js, views.js, grants.js, storage.js) so
// sensitivity heuristics are defined once and all checks agree.

/**
 * Sensitive column categories, ordered by specificity. Each entry maps a
 * logical PII/credential type to a regex tested against the column name AND
 * data type (lowercased, combined). First match wins.
 */
const SENSITIVE_PATTERNS = [
  { name: "cpf", regex: /cpf/i },
  { name: "cnpj", regex: /cnpj/i },
  { name: "government_id", regex: /gov_id|govid|ssn|social_security|national_id|nid/i },
  { name: "email", regex: /email|e_mail/i },
  { name: "phone", regex: /phone|cell|cel|telefone|whatsapp/i },
  { name: "birthdate", regex: /birth|birthday|date_of_birth|birth_date|nascimento/i },
  { name: "health", regex: /health|medical|doctor|patient|therapy|prescription|medic/i },
  { name: "address", regex: /address|addr|street|city|state|zip|postal|cep|neighborhood/i },
  { name: "credentials", regex: /password|pwd|secret|token|api_key|apikey|session|access_token|private_key|client_secret/i },
  { name: "financial", regex: /bank|account|card|credit|debit|ccv|cvv/i },
];

// Aggregate regex for quick boolean checks (used by isSensitiveColumn).
const SENSITIVE_COLUMN_RE = new RegExp(
  SENSITIVE_PATTERNS.map((p) => p.regex.source).join("|"),
  "i"
);

/**
 * Classify a single column by name + type heuristic.
 * @param {string} name — column name (required)
 * @param {string} [dataType=""] — column data type (optional)
 * @returns {string|null} — classification category (e.g. "email", "cpf") or null
 */
// Column names are snake_case. Plain SUBSTRING matching on short tokens produced
// false CRITICALs: `accepted_at` classified as an address (via "cep"),
// `cancelled_at` as a phone (via "cel"), `accounting_firm` as financial (via
// "account"). A CRITICAL that is usually wrong trains people to ignore the ones that
// are right, so the collision-prone SHORT tokens below must match a whole segment.
// Longer and prefix-style patterns (medic*, address, password) keep substring
// matching — `medications` must still classify as health.
const SEGMENT_SEPARATORS = /[^a-z0-9]+/;

// Short tokens that are common substrings of ordinary words. Segment match only.
const STRICT_SEGMENT_WORDS = {
  address: ["cep", "state"],
  phone: ["cel", "cell"],
  credentials: ["token", "session"],
  financial: ["account", "card"],
  government_id: ["ssn", "nid", "govid"],
};

/** Segments of a name, plus a singular form so `access_tokens` matches "token". */
function segmentsOf(name) {
  const segs = String(name).toLowerCase().split(SEGMENT_SEPARATORS).filter(Boolean);
  const out = new Set(segs);
  for (const seg of segs) if (seg.endsWith("s") && seg.length > 3) out.add(seg.slice(0, -1));
  return out;
}

// Usage-metering counters are not credentials. `input_tokens` / `cached_tokens` /
// `tokens_cache_read` are LLM accounting columns; `access_token` is a secret. Name
// alone cannot separate them, so the counter vocabulary is listed explicitly.
const TOKEN_COUNTER_WORDS = new Set([
  "input", "output", "cached", "cache", "total", "count", "usage", "prompt", "completion", "read", "write",
]);

function isTokenCounter(name) {
  const segs = String(name).toLowerCase().split(SEGMENT_SEPARATORS).filter(Boolean);
  if (!segs.some((x) => x === "token" || x === "tokens")) return false;
  return segs.some((x) => TOKEN_COUNTER_WORDS.has(x));
}

/**
 * Classify a single column by name + type heuristic.
 * @param {string} name — column name (required)
 * @param {string} [dataType=""] — column data type (optional)
 * @returns {string|null} — classification category (e.g. "email", "cpf") or null
 */
export function classifyColumn(name, dataType = "") {
  if (!name) return null;
  const type = String(dataType || "").toLowerCase().trim();

  // A boolean holds one bit — it cannot BE a CPF, an email, a phone number, a token
  // or an address. `has_password`, `has_medical_certificate` and `*_enabled` flags are
  // facts ABOUT data, not the data. They may matter, but not as a PII leak.
  if (/^bool(ean)?$/.test(type)) return null;

  if (isTokenCounter(name)) return null;

  const combined = `${String(name)} ${type}`.toLowerCase();
  const segs = segmentsOf(`${name} ${type}`);

  for (const { name: category, regex } of SENSITIVE_PATTERNS) {
    if (!regex.test(combined)) continue;
    const strict = STRICT_SEGMENT_WORDS[category];
    if (!strict) return category;
    // The category matched — but if it matched ONLY via a collision-prone short
    // token, require that token to be a whole segment.
    const withoutStrict = new RegExp(
      regex.source.split("|").filter((alt) => !strict.includes(alt)).join("|") || "(?!)", "i"
    );
    if (withoutStrict.test(combined)) return category;
    if (strict.some((w) => segs.has(w))) return category;
  }
  return null;
}

/**
 * Boolean shortcut: is this column sensitive?
 * @param {string} name — column name
 * @param {string} [dataType=""] — column data type
 * @returns {boolean}
 */
export function isSensitiveColumn(name, dataType = "") {
  return classifyColumn(name, dataType) !== null;
}

/**
 * Scan an array of column descriptors and return the sensitive ones with
 * their classification. Handles both bare strings ("email") and objects
 * ({ name, data_type }) / ({ column_name, data_type }).
 *
 * @param {Array<string|object>} columns
 * @returns {Array<{name: string, data_type: string|null, classification: string}>}
 */
export function scanForSensitiveColumns(columns) {
  if (!Array.isArray(columns)) return [];
  const result = [];
  for (const col of columns) {
    let name, dataType;
    if (typeof col === "string") {
      name = col;
      dataType = null;
    } else if (typeof col === "object" && col !== null) {
      name = col.name || col.column_name;
      dataType = col.data_type || col.type || null;
    }
    const classification = classifyColumn(name, dataType || "");
    if (classification) {
      result.push({ name, data_type: dataType, classification });
    }
  }
  return result;
}

// Re-export the aggregate regex for modules that do quick pre-checks.
export { SENSITIVE_COLUMN_RE };
