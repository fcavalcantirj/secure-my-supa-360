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
export function classifyColumn(name, dataType = "") {
  if (!name) return null;
  const combined = `${String(name)} ${String(dataType || "")}`.toLowerCase();
  for (const { name: category, regex } of SENSITIVE_PATTERNS) {
    if (regex.test(combined)) return category;
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
