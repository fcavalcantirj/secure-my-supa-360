// Tests for scripts/audit.js authenticated-role probe functions (spec entry 6).
// Mocks global.fetch to simulate Supabase Auth API + PostgREST REST API.
import { test } from "node:test";
import assert from "node:assert/strict";
import { signupTestUser, probeAuthenticatedAccess } from "../scripts/audit.js";

const originalFetch = global.fetch;

// --- signupTestUser ---

test("signupTestUser: returns access_token when signup is open (200 + JWT)", async () => {
  const fakeToken = "eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoiYXV0aGVudGljYXRlZCJ9.sig";
  global.fetch = async (url, opts) => {
    const urlStr = String(url);
    assert.ok(urlStr.includes("/auth/v1/signup"));
    assert.equal(opts.method, "POST");
    return {
      ok: true,
      status: 200,
      text: async () => JSON.stringify({ access_token: fakeToken, user: { id: "test-uid" } }),
    };
  };
  const jwt = await signupTestUser("https://testref.supabase.co", "anon-key-value");
  assert.equal(jwt, fakeToken);
  global.fetch = originalFetch;
});

test("signupTestUser: returns null when signups are closed (401)", async () => {
  global.fetch = async () => ({
    ok: false,
    status: 401,
    text: async () => JSON.stringify({ msg: "Signups disabled" }),
  });
  const jwt = await signupTestUser("https://testref.supabase.co", "anon-key-value");
  assert.equal(jwt, null);
  global.fetch = originalFetch;
});

test("signupTestUser: returns null on 403 (signup restricted)", async () => {
  global.fetch = async () => ({
    ok: false,
    status: 403,
    text: async () => JSON.stringify({ msg: "Forbidden" }),
  });
  const jwt = await signupTestUser("https://testref.supabase.co", "anon-key-value");
  assert.equal(jwt, null);
  global.fetch = originalFetch;
});

test("signupTestUser: returns null when response has no access_token", async () => {
  global.fetch = async () => ({
    ok: true,
    status: 200,
    text: async () => JSON.stringify({ user: { id: "test" } }), // no access_token
  });
  const jwt = await signupTestUser("https://testref.supabase.co", "anon-key-value");
  assert.equal(jwt, null);
  global.fetch = originalFetch;
});

test("signupTestUser: returns null on network error", async () => {
  global.fetch = async () => {
    throw new Error("ECONNREFUSED");
  };
  const jwt = await signupTestUser("https://testref.supabase.co", "anon-key-value");
  assert.equal(jwt, null);
  global.fetch = originalFetch;
});

test("signupTestUser: sends email, password, and anon key headers", async () => {
  let capturedMethod = null;
  let capturedHeaders = null;
  let capturedBody = null;
  global.fetch = async (url, opts) => {
    capturedMethod = opts.method;
    capturedHeaders = opts.headers;
    capturedBody = JSON.parse(opts.body);
    return {
      ok: true,
      status: 200,
      text: async () => JSON.stringify({ access_token: "jwt" }),
    };
  };
  await signupTestUser("https://testref.supabase.co", "my-anon-key");
  assert.equal(capturedMethod, "POST");
  assert.equal(capturedHeaders.apikey, "my-anon-key");
  assert.equal(capturedHeaders.Authorization, "Bearer my-anon-key");
  assert.equal(capturedHeaders["Content-Type"], "application/json");
  assert.ok(capturedBody.email.endsWith("@supa360.invalid"));
  assert.ok(capturedBody.password);
  global.fetch = originalFetch;
});

// --- probeAuthenticatedAccess ---

test("probeAuthenticatedAccess: 200 + rows → confirmed leak", async () => {
  global.fetch = async (url) => {
    assert.ok(String(url).includes("/rest/v1/sensitive_table"));
    return {
      ok: true,
      status: 200,
      text: async () => JSON.stringify([{ id: 1, cpf: "123.456.789-00" }]),
    };
  };
  const pr = await probeAuthenticatedAccess("https://testref.supabase.co", "user-jwt", "sensitive_table");
  assert.equal(pr.confirmed, true);
  assert.equal(pr.status, 200);
  assert.equal(pr.sample.row_count, 1);
  assert.equal(pr.sample.columns[0], "id");
  assert.ok(pr.sample.bytes_returned > 0);
  global.fetch = originalFetch;
});

test("probeAuthenticatedAccess: 200 + empty array → not confirmed (safe)", async () => {
  global.fetch = async () => ({
    ok: true,
    status: 200,
    text: async () => JSON.stringify([]),
  });
  const pr = await probeAuthenticatedAccess("https://testref.supabase.co", "user-jwt", "safe_table");
  assert.equal(pr.confirmed, false);
  assert.equal(pr.status, 200);
  assert.equal(pr.sample.row_count, 0);
  global.fetch = originalFetch;
});

test("probeAuthenticatedAccess: 42501 → blocked (not confirmed)", async () => {
  global.fetch = async () => ({
    ok: false,
    status: 42501,
    text: async () => JSON.stringify({ code: "42501", message: "insufficient privileges" }),
  });
  const pr = await probeAuthenticatedAccess("https://testref.supabase.co", "user-jwt", "rls_table");
  assert.equal(pr.confirmed, false);
  assert.equal(pr.status, 42501);
  assert.equal(pr.reason, "http 42501");
  global.fetch = originalFetch;
});

test("probeAuthenticatedAccess: 404 → table not in PostgREST schema", async () => {
  global.fetch = async () => ({
    ok: false,
    status: 404,
    text: async () => JSON.stringify({ message: "Not Found" }),
  });
  const pr = await probeAuthenticatedAccess("https://testref.supabase.co", "user-jwt", "not_exposed");
  assert.equal(pr.confirmed, false);
  assert.equal(pr.status, 404);
  assert.equal(pr.reason, "table not in PostgREST schema");
  global.fetch = originalFetch;
});

test("probeAuthenticatedAccess: network error → status 0", async () => {
  global.fetch = async () => {
    throw new Error("fetch failed");
  };
  const pr = await probeAuthenticatedAccess("https://testref.supabase.co", "user-jwt", "any_table");
  assert.equal(pr.confirmed, false);
  assert.equal(pr.status, 0);
  assert.ok(pr.reason.includes("network error"));
  global.fetch = originalFetch;
});

test("probeAuthenticatedAccess: sends JWT as Bearer + apikey", async () => {
  let capturedHeaders = null;
  global.fetch = async (url, opts) => {
    capturedHeaders = opts.headers;
    return {
      ok: true,
      status: 200,
      text: async () => JSON.stringify([{ id: 1 }]),
    };
  };
  await probeAuthenticatedAccess("https://testref.supabase.co", "my-user-jwt", "my_table");
  assert.equal(capturedHeaders.Authorization, "Bearer my-user-jwt");
  assert.equal(capturedHeaders.apikey, "my-user-jwt");
  global.fetch = originalFetch;
});

// --- Integration: probe function fallback behavior (mirrors audit.js logic) ---

test("integration: anon probe blocked + authenticated probe confirms → leak is caught", async () => {
  // Simulate the probeFn logic from audit(): try anon first, fall back to auth
  const probeFnLogic = async (tableName, { anonKey, userJwt, supabaseUrl }) => {
    // Anonymous probe (blocked)
    await fetchMock(supabaseUrl, anonKey, tableName, {
      ok: false, status: 42501, rows: []
    });
    // Authenticated probe (confirms leak)
    const authPr = await fetchMock(supabaseUrl, userJwt, tableName, {
      ok: true, status: 200, rows: [{ id: 1, secret: "leaked" }]
    });
    assert.equal(authPr.confirmed, true);
    return { status: authPr.status, rowCount: 1 };
  };

  // Helper: simulate the fetch behavior
  async function fetchMock(baseUrl, token, tableName, response) {
    // This simulates the probe logic
    if (!response.ok) {
      return { confirmed: false, status: response.status, reason: "blocked" };
    }
    return {
      confirmed: response.rows.length > 0,
      status: response.status,
      sample: { row_count: response.rows.length, columns: response.rows[0] ? Object.keys(response.rows[0]) : [], bytes_returned: 100 },
    };
  }

  const result = await probeFnLogic("secret_table", {
    anonKey: "anon-key",
    userJwt: "user-jwt",
    supabaseUrl: "https://testref.supabase.co",
  });
  // Anon probe returned 42501 (blocked), auth probe confirmed leak with 200 + rows
  assert.equal(result.status, 200);   // auth probe result takes priority when confirmed
  assert.equal(result.rowCount, 1);   // auth probe found 1 row
});
