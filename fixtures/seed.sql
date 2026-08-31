-- =====================================================================
-- Golden vulnerable fixture (spec entry 27 — regression gate for the 360).
--
-- This seed.sql creates a deliberately vulnerable Supabase project state.
-- It is the source of truth for fixtures/seed.sql and the reference that
-- test/golden-harness.test.js mirrors as JS fixture data (the pure check
-- functions consume DB query results, not live SQL — so the test mirrors
-- the *state* this SQL describes, row-for-row).
--
-- DO NOT run against any real production project.
-- Use a throwaway Supabase project ref — ask the architect in the room.
-- =====================================================================

-- 1. RLS-ON + permissive USING(true) table (the USING(true) miss).
--    RLS is enabled, but the policy allows everyone to read. A naive on/off
--    + policy-count check would miss this entirely.
CREATE TABLE public.sensitive_photos (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  patient_cpf text NOT NULL,     -- PII: CPF (Brazilian govt id)
  url text NOT NULL
);
ALTER TABLE public.sensitive_photos ENABLE ROW LEVEL SECURITY;
CREATE POLICY "allow public access to sensitive_photos"
  ON public.sensitive_photos
  FOR ALL
  TO public
  USING (true)
  WITH CHECK (true);
GRANT SELECT ON public.sensitive_photos TO anon;

-- 2. RLS-OFF table with anon grants (classic, original tool caught this).
CREATE TABLE public.public_notes (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  body text NOT NULL,
  author_id uuid
);
ALTER TABLE public.public_notes DISABLE ROW LEVEL SECURITY;
GRANT SELECT, INSERT, DELETE ON public.public_notes TO anon;
GRANT SELECT, INSERT, DELETE ON public.public_notes TO authenticated;

-- 3. Table with RLS ON + permissive INSERT policy, no WITH CHECK (write leak).
CREATE TABLE public.comments (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  body text NOT NULL,
  user_id uuid
);
ALTER TABLE public.comments ENABLE ROW LEVEL SECURITY;
CREATE POLICY "comments_owner_write"
  ON public.comments
  FOR INSERT
  TO anon
  WITH CHECK (true);
GRANT INSERT ON public.comments TO anon;

-- 4. Security DEFINER function, executable by anon, NO internal auth check,
--    with dynamic SQL from arguments (injection + privilege-escalation vector).
CREATE OR REPLACE FUNCTION public.attach_company_admin(account_id uuid)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
BEGIN
  EXECUTE 'SELECT * FROM account_admins WHERE id = ' || account_id;
  RETURN;
END;
$$;
GRANT EXECUTE ON FUNCTION public.attach_company_admin(uuid) TO anon;
REVOKE EXECUTE ON FUNCTION public.attach_company_admin(uuid) FROM authenticated;

-- 5. Security-DEFINER view over an RLS-locked table, leaking rows to anon.
CREATE TABLE public.tenant_data (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  tenant_id uuid NOT NULL,
  secret_value text NOT NULL
);
ALTER TABLE public.tenant_data ENABLE ROW LEVEL SECURITY;
CREATE POLICY "tenant_isolation" ON public.tenant_data
  FOR SELECT USING (tenant_id = auth.uid()::uuid);
REVOKE ALL ON public.tenant_data FROM anon;

CREATE OR REPLACE VIEW public.v_tenant_data
WITH (security_invoker = false) AS
  SELECT id, tenant_id, secret_value FROM public.tenant_data;
GRANT SELECT ON public.v_tenant_data TO anon;

-- 6. Public bucket + anon-upload / anon-delete storage policies (anon-upload-style).
-- (Bucket + policies are configured via the Supabase API, documented in the
--  Management API config section below; the SQL equivalent for the policy
--  surface is the anon INSERT/UPDATE/DELETE grants on storage.objects.)
-- The seed.sql here is the DB-level equivalent:
INSERT INTO storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
VALUES ('media', 'media', true, null, null)
ON CONFLICT (id) DO UPDATE SET public = true;

-- Anon can READ, INSERT (upload), UPDATE (tamper), DELETE (wipe) objects.
-- In a real project these are storage.objects RLS policies:
--   CREATE POLICY "anon read" ON storage.objects FOR SELECT TO anon USING (bucket_id = 'media');
--   CREATE POLICY "anon upload" ON storage.objects FOR INSERT TO anon WITH CHECK (bucket_id = 'media');
--   CREATE POLICY "anon tamper" ON storage.objects FOR UPDATE TO anon USING (bucket_id = 'media');
--   CREATE POLICY "anon wipe" ON storage.objects FOR DELETE TO anon USING (bucket_id = 'media');

-- 7. Column-level anon SELECT grant on a sensitive column.
CREATE TABLE public.user_profiles (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  email text NOT NULL,        -- sensitive
  phone text,                 -- sensitive
  full_name text
);
ALTER TABLE public.user_profiles ENABLE ROW LEVEL SECURITY;
GRANT SELECT (id, email) ON public.user_profiles TO anon;  -- leaks email even with RLS

-- 8. Custom exposed schema (Data API exposes things it shouldn't).
CREATE SCHEMA custom_integration;
CREATE TABLE custom_integration.legacy_secrets (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  api_key text NOT NULL
);
GRANT SELECT ON custom_integration.legacy_secrets TO anon;
-- (Data API 'exposed schemas' includes custom_integration via config — see Management API section)

-- 9. Realtime publication includes tables WITHOUT RLS.
-- (Supabase Realtime publishes supabase_realtime; a table in the publication
--  with RLS disabled broadcasts row changes to any subscriber — a direct leak.)
-- SQL equivalent: ALTER PUBLICATION supabase_realtime ADD TABLE public.public_notes;
-- (realtime.messages has no RLS or policies: broadcast/presence writable by anon)
-- (Done via the realtime publication on the project.)

-- 10. pg_cron job with an embedded bearer token (secrets-in-cron anti-pattern).
-- (Requires the pg_cron extension; the command below is the seed-equivalent.)
-- SELECT cron.schedule('net-http', '* * * * *',
--   $$SELECT net.http_post('https://api.example.com/hook', 'bearer ey_token_here', '{"x":1}')$$);

-- 11. Default privileges leaking to anon on future tables (owner = postgres).
ALTER DEFAULT PRIVILEGES FOR ROLE postgres
  GRANT SELECT, INSERT, DELETE ON TABLES TO anon;
ALTER DEFAULT PRIVILEGES FOR ROLE postgres
  GRANT SELECT, INSERT, DELETE ON TABLES TO authenticated;

-- ====================================================================
-- Management API config (not DB-level SQL — set via PATCH /config/* endpoints):
--   Auth config (entry 14 fixture):
--     password_min_length=6, password_hibp_enabled=false, mailer_autoconfirm=true,
--     disable_signup=false, external_anonymous_users_enabled=false,
--     security_captcha_enabled=false, mfa_enabled=false, jwt_exp=36000,
--     uri_allow_list=[] (open redirect), rate_limit_email=0, rate_limit_graphql=0
--
--   Network / DB (entry 18 fixture):
--     network_restrictions.enabled=false, db_ssl=false, pool_mode=session
--
--   Edge Functions (entry 17 fixture):
--     function with verify_jwt=false, cors=* (wildcard)
--
--   Data API (entry 21 fixture):
--     auto_expose=true, exposed_schemas=['public','custom_integration']
--
--   Extensions (entry 19 fixture):
--     http extension installed, vault decrypted_secrets readable by anon
-- ====================================================================
