// Pure auth-configuration analyzer. Spec entry 14 (coverage-auth deep).
// Takes the /config/auth response object + project ref, returns contract-shaped
// findings. No I/O, no fetch — the API call stays in audit.js. Unit-tested with
// mock auth-config objects.
//
// Extends the 4 checks that lived inline in audit.js (signups_no_confirm,
// anonymous_signins, weak_password, no_captcha) with:
//   auth_hibp_disabled, auth_mfa_disabled, auth_jwt_exp_too_long,
//   auth_redirect_allowlist_open, auth_rate_limit_missing.

const AUTH_PATH = (ref) => `/v1/projects/${ref}/config/auth`;

function mgmtFix(ref, body, priorValues, dashboard = null) {
  return {
    sql: [],
    rollback_sql: [],
    dashboard_action: dashboard,
    management_api_action: { method: "PATCH", path: AUTH_PATH(ref), body },
    rollback_management_api_action: { method: "PATCH", path: AUTH_PATH(ref), body: priorValues },
    requires_service_role: false,
  };
}

function makeFinding(check, severity, target, evidence, fix) {
  return {
    check,
    category: "coverage-auth",
    confidence: "inferred",
    severity,
    target,
    evidence,
    fix,
  };
}

/**
 * Analyze a Supabase /config/auth object for auth hardening gaps.
 * @param {object} config  - the raw /config/auth JSON response
 * @param {string} ref     - project ref (for management_api_action paths)
 * @returns {Array} contract-shaped findings (id added by normalizeFinding)
 */
export function analyzeAuthConfig(config, ref = "unknown") {
  const findings = [];
  if (!config || typeof config !== "object") return findings;

  // 1. Signups enabled without email confirmation
  if (config.disable_signup === false && config.mailer_autoconfirm === true) {
    findings.push(makeFinding(
      "auth_signups_enabled_no_confirm",
      "medium",
      "auth:signups",
      { signups_enabled: true, autoconfirm: true },
      mgmtFix(ref, { mailer_autoconfirm: false }, { mailer_autoconfirm: config.mailer_autoconfirm })
    ));
  }

  // 2. Anonymous sign-ins enabled
  if (config.external_anonymous_users_enabled === true) {
    findings.push(makeFinding(
      "anonymous_signins_enabled",
      "high",
      "auth:anonymous",
      { external_anonymous_users_enabled: true },
      mgmtFix(ref, { external_anonymous_users_enabled: false }, { external_anonymous_users_enabled: config.external_anonymous_users_enabled })
    ));
  }

  // 3. Weak password policy (min length < 8)
  if (typeof config.password_min_length === "number" && config.password_min_length < 8) {
    findings.push(makeFinding(
      "weak_password_policy",
      "medium",
      "auth:password",
      { password_min_length: config.password_min_length, password_required_characters: config.password_required_characters },
      mgmtFix(ref, {
        password_min_length: 12,
        password_required_characters: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()",
      }, {
        password_min_length: config.password_min_length,
        password_required_characters: config.password_required_characters,
      })
    ));
  }

  // 4. No CAPTCHA on auth endpoints (when signups are open)
  if (config.security_captcha_enabled === false && config.disable_signup === false) {
    findings.push(makeFinding(
      "no_captcha_on_auth",
      "medium",
      "auth:captcha",
      { security_captcha_enabled: false },
      // DASHBOARD-ONLY on purpose. Enabling captcha requires a provider secret the
      // tool cannot know. The previous auto-fix PATCHed the literal string
      // "<your_secret>" into the project's live auth config and enabled captcha with
      // it — which breaks sign-up for real users — and its rollback restored only
      // security_captcha_enabled, leaving the bogus provider and secret behind.
      // A fix that needs a value only the operator has is a dashboard action, not an
      // auto-fix.
      {
        sql: [],
        rollback_sql: [],
        dashboard_action:
          "Dashboard -> Authentication -> Attack Protection -> enable CAPTCHA, choose a provider (hCaptcha/Turnstile) and paste YOUR provider secret",
        management_api_action: null,
        rollback_management_api_action: null,
        requires_service_role: false,
      }
    ));
  }

  // 5. HIBP password breach checking disabled
  if (config.password_hibp_enabled === false) {
    findings.push(makeFinding(
      "auth_hibp_disabled",
      "medium",
      "auth:password",
      { password_hibp_enabled: false },
      mgmtFix(ref, { password_hibp_enabled: true }, { password_hibp_enabled: config.password_hibp_enabled })
    ));
  }

  // 6. MFA not enforced
  if (config.mfa_enabled === false) {
    findings.push(makeFinding(
      "auth_mfa_disabled",
      "high",
      "auth:mfa",
      { mfa_enabled: false },
      mgmtFix(ref, { mfa_enabled: true }, { mfa_enabled: config.mfa_enabled }, "Dashboard -> Authentication -> Multi-Factor -> Enforce MFA for all users")
    ));
  }

  // 7. JWT expiration too long (> 8 hours = 28800s)
  if (typeof config.jwt_exp === "number" && config.jwt_exp > 28800) {
    findings.push(makeFinding(
      "auth_jwt_exp_too_long",
      "medium",
      "auth:jwt",
      { jwt_exp: config.jwt_exp, recommended: 3600 },
      mgmtFix(ref, { jwt_exp: 3600 }, { jwt_exp: config.jwt_exp })
    ));
  }

  // 8. Open redirect allowlist (empty array = accepts any redirect URI)
  if (Array.isArray(config.uri_allow_list) && config.uri_allow_list.length === 0) {
    findings.push(makeFinding(
      "auth_redirect_allowlist_open",
      "high",
      "auth:redirect",
      { uri_allow_list: [], recommendation: "restrict to known redirect URIs" },
      mgmtFix(ref, { uri_allow_list: ["https://your-app.com/callback"] }, { uri_allow_list: config.uri_allow_list })
    ));
  }

  // 9. Missing rate limits (no rate_limit_* config set)
  const hasRateLimits = Object.keys(config).some(
    (k) => k.startsWith("rate_limit_") && config[k] != null
  );
  if (!hasRateLimits) {
    findings.push(makeFinding(
      "auth_rate_limit_missing",
      "medium",
      "auth:rate_limit",
      { rate_limit_keys_present: Object.keys(config).filter((k) => k.startsWith("rate_limit_")) },
      mgmtFix(ref, {}, {}, "Dashboard -> Authentication -> Rate Limiting -> Configure rate limits for all auth endpoints")
    ));
  }

  return findings;
}
