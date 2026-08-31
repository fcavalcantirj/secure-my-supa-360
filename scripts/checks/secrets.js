// Static secret scanner. Spec entry 16 (coverage-secrets).
//
// Pure + DB-free + IO-free: takes (path, content[, opts]) and returns findings.
// The file walk (node readirSync) lives in discover.js; this module owns the
// *scan* so it can be unit-tested with mock file contents — no fs, no git, no
// live DB. Reuses discover.js's walk via scanRepo's `files` input.
//
// Finds the classes the original tool MISSED entirely (committed PATs, connstrings,
// third-party keys, service_role JWTs in code, NEXT_PUBLIC_/VITE_ exposure) and
// adds the .gitignore/tracking hygiene check. Legacy JWT anon keys and modern
// sb_publishable_ keys are public-by-design and are recorded as context only
// (NOT findings).

const JWT_RE = /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g;
const SB_PAT_RE = /sbp_[a-zA-Z0-9_]{20,}/g;
const SUPABASE_SECRET_RE = /supabase_secret_[a-zA-Z0-9_]{20,}/g;
const CONNSTRING_RE = /(?:postgres(?:ql)?):\/\/[^:\s'"]+:[^\s'"]+@/g;
const AWS_KEY_RE = /AKIA[0-9A-Z]{16}/g;
const GH_PAT_RE = /ghp_[A-Za-z0-9]{36}/g;
const GH_OAUTH_RE = /gho_[A-Za-z0-9]{36}/g;
const STRIPE_SK_RE = /sk_live_[A-Za-z0-9]{16,}/g;
const SLACK_RE = /xox[baprs]-[A-Za-z0-9-]{10,}/g;
// sb_publishable_ is the modern PUBLIC anon key (public-by-design, not a finding).
const SB_PUBLISHABLE_RE = /sb_publishable_[a-zA-Z0-9_]{16,}/g;
// Any NEXT_PUBLIC_/VITE_ var assignment whose VALUE is a secret (value captured greedily
// up to whitespace/quote/comment). The var-name suffix filter is intentionally dropped —
// the value check (isSecret) + anon/publishable exclusion is what gates it.
const ENV_VAR_RE = /(?<![A-Z0-9_])(NEXT_PUBLIC_|VITE_)([A-Z0-9_]+)\s*=\s*([^\s'"#]+)/g;

const DOTENV_RE = /(^|\/)(\.env(\..*)?)$/;

// Strict redaction for any secret preview stored in evidence — 8 chars + "…" is
// too short to satisfy ANY secret regex (PATs need 20+ chars post-prefix, JWTs
// need 3 dotted parts, connstrings need user:pass@, AWS needs AKIA+16). This
// guarantees the contract's own scanForSecrets self-scan never fires on output.
export function redact(secret) {
  return secret ? String(secret).slice(0, 8) + "…" : "";
}

/** Decode a JWT payload (without verification) → parsed payload or null. */
export function decodeJwt(token) {
  const parts = String(token).split(".");
  if (parts.length !== 3) return null;
  try {
    const b64 = parts[1].replace(/-/g, "+").replace(/_/g, "/");
    const pad = (4 - (b64.length % 4)) % 4;
    const json = Buffer.from(b64 + "==".slice(0, pad), "base64").toString("utf8");
    return JSON.parse(json);
  } catch {
    return null;
  }
}

/** role claim of a JWT, or null if not a JWT / unparseable. */
export function jwtRole(token) {
  const p = decodeJwt(token);
  return p && p.role ? String(p.role) : null;
}

function dedupeFindings(findings) {
  const seen = new Set();
  return findings.filter((f) => {
    // Include evidence.preview so multiple distinct secrets of the SAME check
    // type in one file (e.g. committed_thirdparty_key for AWS + Stripe + GH)
    // are not collapsed into one.
    const k = `${f.check}:${f.target}:${f.evidence?.preview || ""}`;
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });
}

function fixNote(note) {
  return {
    sql: [note],
    rollback_sql: [`-- No automated rollback: this fix is a manual/source change. Revert the change to restore prior state.`],
    dashboard_action: null,
    management_api_action: null,
    requires_service_role: false,
  };
}

// Classify one detected raw secret value into a finding (or null if benign/public).
function secretFinding(check, severity, path, evidence, fixSql) {
  return {
    check,
    category: "coverage-secrets",
    severity,
    confidence: "confirmed",
    target: path,
    evidence,
    fix: fixNote(fixSql),
  };
}

/**
 * Scan a single file's content for committed secrets. Emits ALL detections
 * regardless of git-tracking; scanRepo applies the tracked/suppression filter.
 * @param {string} path  - file path (used as the finding target)
 * @param {string} content
 * @returns {Array} contract-shaped findings (no id; normalizeFinding adds it)
 */
export function scanFile(path, content) {
  const out = [];
  if (!content) return out;
  const text = String(content);
  let m;

  // 1. JWTs: decode the role. service_role -> finding. anon/authenticated/public
  //    keys are public-by-design -> NOT findings (recorded as context by scanRepo).
  const jwtRe = new RegExp(JWT_RE.source, JWT_RE.flags);
  while ((m = jwtRe.exec(text)) !== null) {
    const token = m[0];
    const role = jwtRole(token);
    if (role === "service_role") {
      out.push(secretFinding("committed_service_role_jwt", "critical", path, { kind: "jwt", role: "service_role", preview: redact(token) },
        "-- No SQL fix. Rotate the service_role key (Dashboard → Project Settings → API → Service Role → Generate new) and purge it from git history."));
    }
    // role anon/authenticated/unknown: public-by-design or unclassifiable-in-context; not a finding
  }

  // 2. Supabase PATs (sbp_) — always critical when committed
  const patRe = new RegExp(SB_PAT_RE.source, SB_PAT_RE.flags);
  while ((m = patRe.exec(text)) !== null) {
    out.push(secretFinding("committed_supabase_pat", "critical", path, { kind: "pat", preview: redact(m[0]) },
      "-- No SQL fix. Revoke the PAT (Dashboard → Account → Access Tokens) and remove from source."));
  }

  // 3. supabase_secret_ values
  const secretRe = new RegExp(SUPABASE_SECRET_RE.source, SUPABASE_SECRET_RE.flags);
  while ((m = secretRe.exec(text)) !== null) {
    out.push(secretFinding("committed_supabase_secret", "critical", path, { kind: "supabase_secret", preview: redact(m[0]) },
      "-- Rotate the Supabase secret in project settings and remove from source."));
  }

  // 4. DB connection strings with embedded password
  const connRe = new RegExp(CONNSTRING_RE.source, CONNSTRING_RE.flags);
  while ((m = connRe.exec(text)) !== null) {
    out.push(secretFinding("committed_db_connstring", "high", path, { kind: "connstring", preview: redact(m[0]) },
      "-- Rotate the DB password (Dashboard → Project Settings → Database → Password) and remove the connstring from source; use SUPABASE_DB_URL secret instead."));
  }

  // 5. Third-party keys (AWS / GitHub / Stripe / Slack)
  const thirdparty = [
    [AWS_KEY_RE, "aws_access_key_id", "high", "AWS access key id (rotate in AWS IAM)"],
    [GH_PAT_RE, "github_pat", "high", "GitHub PAT (revoke at github.com/settings/tokens)"],
    [GH_OAUTH_RE, "github_oauth_token", "high", "GitHub OAuth token (revoke in the app)"],
    [STRIPE_SK_RE, "stripe_secret_key", "critical", "Stripe secret key (rotate in Stripe dashboard)"],
    [SLACK_RE, "slack_token", "high", "Slack token (rotate in Slack app config)"],
  ];
  for (const [re, kind, severity, remediation] of thirdparty) {
    const r = new RegExp(re.source, "g");
    while ((m = r.exec(text)) !== null) {
      out.push(secretFinding("committed_thirdparty_key", severity, path, { kind, preview: redact(m[0]) },
        `-- No SQL fix. ${remediation} and remove from source.`));
    }
  }

  // 6. NEXT_PUBLIC_ / VITE_ exposure: a browser-shipped var holding a non-anon,
  //    non-publishable secret. (NEXT_PUBLIC_/VITE_-prefixed vars are inlined into
  //    the client bundle, so any non-public secret there is exposed to everyone.)
  const npRe = new RegExp(ENV_VAR_RE.source, "g");
  while ((m = npRe.exec(text)) !== null) {
    const value = m[3] || "";
    const isAnonJwt = jwtRole(value) === "anon";
    const isPublishable = SB_PUBLISHABLE_RE.test(value);
    const isSecret = JWT_RE.test(value) || SB_PAT_RE.test(value) || SUPABASE_SECRET_RE.test(value) || CONNSTRING_RE.test(value);
    if (isSecret && !isAnonJwt && !isPublishable) {
      out.push({
        check: "env_secret_exposed_to_browser",
        category: "coverage-secrets",
        severity: "critical",
        confidence: "confirmed",
        target: path,
        evidence: {
          var: `${m[1]}${m[2]}`,
          kind: "env_var",
          preview: redact(value),
        },
        fix: {
          sql: ["-- No SQL fix. Move the secret out of any NEXT_PUBLIC_*/VITE_ var (these are inlined into the browser bundle); keep only the public anon/publishable key there."],
          rollback_sql: ["-- No automated rollback: restore the original NEXT_PUBLIC_*/VITE_ variable if needed (revert the source change)."],
          dashboard_action: "Ensure only the public anon key (sb_publishable_*) is exposed to the client; store service_role/PATs server-side only.",
          management_api_action: null,
          requires_service_role: false,
        },
      });
    }
  }

  return dedupeFindings(out);
}

/** Context note (NOT a finding): record the anon-key format found, if any. */
export function anonKeyContext(text) {
  if (!text) return { anon_key_format: null };
  const hasPublishable = SB_PUBLISHABLE_RE.test(text);
  if (hasPublishable) return { anon_key_format: "sb_publishable_ (modern, public-by-design)" };
  if (new RegExp(JWT_RE.source, "g").test(text)) return { anon_key_format: "legacy_jwt_anon (public-by-design)" };
  return { anon_key_format: null };
}

function relPath(p) {
  return (p || "").replace(/^\.\//, "");
}

/**
 * Scan a repo's file set for committed secrets.
 * @param {Array<{path:string, content:string}>} files - output of discover.js's walk
 * @param {object} [opts]
 * @param {string[]} [opts.trackedPaths=[]] - git-tracked file paths (from `git ls-files`)
 * @returns {{ findings: Array, context: object }} contract-shaped findings + context notes
 */
export function scanRepo(files, opts = {}) {
  const trackedSet = new Set((opts.trackedPaths || []).map(relPath));
  const findings = [];
  let anonContext = { anon_key_format: null };

  for (const f of files) {
    if (!f || !f.path) continue;
    const tracked = trackedSet.has(relPath(f.path));
    const scanned = scanFile(f.path, f.content);

    for (const s of scanned) {
      // Secrets in gitignored (non-tracked) files are suppressed but kept for auditability.
      s.suppressed = !tracked;
      if (s.suppressed) {
        s.suppressed_reason = "secret in gitignored file (not committed)";
      }
      findings.push(s);
    }

    // .env* file that IS tracked -> hygiene finding (regardless of secrets inside)
    if (tracked && DOTENV_RE.test(f.path)) {
      findings.push({
        check: "dotenv_tracked",
        category: "coverage-secrets",
        severity: "medium",
        confidence: "confirmed",
        target: f.path,
        evidence: { reason: ".env file is git-tracked (committed); secrets here are exposed in git history" },
        fix: fixNote("-- No SQL fix. git rm --cached <file> && echo '<file>' >> .gitignore && git commit -m 'Stop tracking env file'"),
      });
    }

    // accumulate anon-key format context across env/config files
    if (f.content) {
      const ctx = anonKeyContext(f.content);
      if (ctx.anon_key_format) anonContext = ctx;
    }
  }

  return { findings, context: anonContext };
}
