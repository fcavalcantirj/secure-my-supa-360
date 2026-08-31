-- Teardown for fixtures/seed.sql — reverses every CREATE/GRANT.
-- Run via `supabase-security lab teardown <ref>` to restore a lab project
-- to its pre-seed state. Idempotent (IF EXISTS).
-- DO NOT run against any production project.

-- 1. Drop tables created by seed (RLS + policies + grants are dropped with CASCADE)
DROP TABLE IF EXISTS public.sensitive_photos CASCADE;
DROP TABLE IF EXISTS public.public_notes CASCADE;
DROP TABLE IF EXISTS public.comments CASCADE;
DROP TABLE IF EXISTS public.user_profiles CASCADE;
DROP TABLE IF EXISTS public.tenant_data CASCADE;

-- 2. Drop the security-definer view (drop table first via CASCADE, then explicit)
DROP VIEW IF EXISTS public.v_tenant_data;

-- 3. Drop the security-definer function
DROP FUNCTION IF EXISTS public.attach_company_admin(uuid) CASCADE;

-- 4. Drop the custom schema (table + grants)
DROP SCHEMA IF EXISTS custom_integration CASCADE;

-- 5. The seeded storage bucket is deleted via the Storage API in lab.js
--    (storage.protect_delete() blocks direct SQL DELETE from storage.buckets).

-- 6. Revoke default privileges set by seed on future tables
ALTER DEFAULT PRIVILEGES FOR ROLE postgres
  REVOKE SELECT, INSERT, DELETE ON TABLES FROM anon;
ALTER DEFAULT PRIVILEGES FOR ROLE postgres
  REVOKE SELECT, INSERT, DELETE ON TABLES FROM authenticated;
