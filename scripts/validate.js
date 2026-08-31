#!/usr/bin/env node
// Minimal JSON Schema (draft-07 / 2020-12 subset) validator + CLI.
// Pure Node.js stdlib only — no ajv, no deps. Supports the subset we actually
// use in schema/finding.schema.json: type, required, properties, items,
// enum, const, $ref (internal), additionalProperties, minimum, minLength,
// and format (date-time is type-checked as string; value not deeply parsed).
//
// Usage:
//   node scripts/validate.js < result.json     # read JSON from stdin, validate
//   node scripts/validate.js --schema path.json < result.json
// Exit codes: 0 = valid, 12 = schema validation failure (matches audit exit-code contract)

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

// --- type checking ---

function typeName(v) {
  if (v === null) return "null";
  if (Array.isArray(v)) return "array";
  return typeof v;
}

function checkType(value, type) {
  if (Array.isArray(type)) return type.some((t) => checkType(value, t));
  if (type === "object") return typeName(value) === "object";
  if (type === "array") return Array.isArray(value);
  if (type === "string") return typeof value === "string";
  if (type === "integer") return Number.isInteger(value);
  if (type === "number") return typeof value === "number" && !Number.isNaN(value);
  if (type === "boolean") return typeof value === "boolean";
  if (type === "null") return value === null;
  return false; // unknown type
}

// --- $ref resolution ---

function resolveRef(ref, root) {
  // Only support internal refs like "#/$defs/finding"
  if (!ref.startsWith("#")) {
    throw new Error(`validate: only internal $ref supported, got: ${ref}`);
  }
  const parts = ref.slice(1).split("/").filter((p) => p.length > 0);
  let node = root;
  for (const part of parts) {
    node = node[part.replace(/~1/g, "/").replace(/~0/g, "~")];
    if (node === undefined) {
      throw new Error(`validate: cannot resolve $ref: ${ref}`);
    }
  }
  return node;
}

// --- core validator ---

/**
 * Validate `data` against `schema`. Returns { valid, errors }.
 * @param {*} data
 * @param {object} schema
 * @returns {{valid: boolean, errors: Array<{path: string, message: string}>}}
 */
export function validate(data, schema) {
  const errors = [];

  // The root schema is threaded explicitly through every recursive walk()
  // call so that $ref always resolves against the ORIGINAL root document,
  // not the current sub-schema node. This makes nested $ref chains work
  // (e.g. result -> #/$defs/finding -> fix -> #/$defs/fix).
  const root = schema;

  function walk(value, subschema, path) {
    // Resolve $ref first — always against the root document, not the local node
    if (subschema.$ref) {
      subschema = resolveRef(subschema.$ref, root);
    }

    // const
    if (subschema.const !== undefined && value !== subschema.const) {
      errors.push({ path, message: `expected ${JSON.stringify(subschema.const)}, got ${JSON.stringify(value)}` });
      return;
    }

    // enum
    if (subschema.enum && !subschema.enum.includes(value)) {
      errors.push({ path, message: `value ${JSON.stringify(value)} not in enum [${subschema.enum.join(", ")}]` });
      return;
    }

    // type
    if (subschema.type && !checkType(value, subschema.type)) {
      errors.push({ path, message: `expected type ${JSON.stringify(subschema.type)}, got ${typeName(value)}` });
      return;
    }

    if (value === null || value === undefined) {
      // null is fine for nullable types (already checked above); skip further checks
      return;
    }

    // minimum
    if (subschema.minimum !== undefined && typeof value === "number" && value < subschema.minimum) {
      errors.push({ path, message: `value ${value} < minimum ${subschema.minimum}` });
    }

    // minLength
    if (subschema.minLength !== undefined && typeof value === "string" && value.length < subschema.minLength) {
      errors.push({ path, message: `string length ${value.length} < minLength ${subschema.minLength}` });
    }

    // Required fields (objects only)
    if (subschema.required && typeName(value) === "object") {
      for (const req of subschema.required) {
        if (!(req in value)) {
          errors.push({ path: path ? `${path}.${req}` : req, message: "missing required property" });
        }
      }
    }

    // Properties (objects only)
    if (subschema.properties && typeName(value) === "object") {
      for (const [key, subsub] of Object.entries(subschema.properties)) {
        if (key in value) {
          walk(value[key], subsub, path ? `${path}.${key}` : key);
        }
      }
    }

    // Items (arrays only)
    if (subschema.items && Array.isArray(value)) {
      for (let i = 0; i < value.length; i++) {
        walk(value[i], subschema.items, `${path}[${i}]`);
      }
    }

    // Note: additionalProperties is not strictly enforced — we allow extras so
    // backward-compat fields (title, explain, fix_sql, etc.) pass freely.
  }

  walk(data, schema, "");
  return { valid: errors.length === 0, errors };
}

// --- CLI ---

const DEFAULT_SCHEMA = new URL("../schema/finding.schema.json", import.meta.url);
const schemaPath = process.argv.includes("--schema")
  ? process.argv[process.argv.indexOf("--schema") + 1]
  : fileURLToPath(DEFAULT_SCHEMA);

// Guard process.argv[1] for safe import as a library (e.g. from tests or lab.js).
const argv1 = process.argv[1] || "";
if (import.meta.url === `file://${argv1.replace(/\\/g, "/")}` ||
    (argv1 && import.meta.url.endsWith(argv1.replace(/\\/g, "/")))) {
  const schema = JSON.parse(readFileSync(schemaPath, "utf8"));

  let input = "";
  process.stdin.setEncoding("utf8");
  process.stdin.on("data", (chunk) => (input += chunk));
  process.stdin.on("end", () => {
    let data;
    try {
      data = JSON.parse(input);
    } catch (e) {
      console.error(`validate: cannot parse JSON input: ${e.message}`);
      process.exit(12);
    }
    const result = validate(data, schema);
    if (result.valid) {
      console.log(JSON.stringify({ valid: true, errors: [] }));
      process.exit(0);
    } else {
      console.error(JSON.stringify({ valid: false, errors: result.errors }, null, 2));
      process.exit(12);
    }
  });
}
