# secure-my-supa-360

Audits a Supabase project for exposure — RLS, grants, anon-callable RPCs, storage, edge functions,
auth config — and generates the SQL to close what it finds. Runs from your machine against
Supabase's own Management API. No third-party service, zero runtime dependencies, Node >= 18.

## Where this came from

Forked from **[Perufitlife/supabase-security-skill](https://github.com/Perufitlife/supabase-security-skill)**
by Renzo Madueno (MIT). That project is the origin of this one and remains under his copyright —
`LICENSE` retains both notices.

We forked rather than contributed upstream because what we needed changed the shape of the thing:
the original is a single-file auditor that reports, and we needed one that **remediates and can
prove its remediation is reversible** — which meant a check/remediate/rollback architecture, a
disposable-lab harness to test the write path against a real Postgres, and a test suite. That is a
different project, not a patch.

## Why we built it

**Grants and policies drift silently.** A Supabase project accumulates `SECURITY DEFINER` functions
technically callable by `anon`, tables where RLS is on but the policy is `USING (true)`, buckets
that accept anonymous writes, default privileges left from whatever the platform default was when
the project was created. Nothing announces any of it. You learn it from an audit or from an incident.

**RLS correctness and RLS performance are the same problem.** Supabase's own
[RLS performance and best practices](https://supabase.com/docs/guides/troubleshooting/rls-performance-and-best-practices-Z5Jjwv)
guide documents patterns that are easy to get wrong and expensive when you do — and every one is
mechanically detectable, so we detect them:

| Supabase recommends | Check |
|---|---|
| Wrap `auth.uid()` / `auth.jwt()` in a subselect so the optimizer builds an `initPlan` and caches it instead of re-evaluating per row — their measurements: 179 ms → 9 ms, and 178 s → 12 ms on a complex policy | `rls_unwrapped_auth_fn` |
| Index policy columns that aren't already a PK or unique — they report >100x on large tables | `rls_unindexed_policy_column` |
| Name the role with `TO authenticated`; never leave a policy open to `public` | `rls_policy_public_role` |
| Restructure policy joins to compare a row column against fixed join data rather than joining per row | `rls_policy_join` |

A policy re-evaluating `auth.uid()` for every row is not a performance nit — under load it is a
denial-of-service surface. Reporting it as a security finding is deliberate.

## Supabase's own Production Checklist

The mechanically-checkable items from
[Supabase's Production Checklist](https://supabase.com/docs/guides/deployment/going-into-prod)
map to checks here. Where Supabase names a specific threshold, we use theirs:

| Checklist item | Check |
|---|---|
| Enable RLS on all tables | `rls_disabled`, `rls_no_policies_with_anon_grants` |
| Turn on SSL enforcement | `db_ssl_disabled` |
| Enable network restrictions | `db_no_network_restrictions` |
| Enable email confirmations | `auth_signups_enabled_no_confirm` |
| Set OTP expiry to 3600s or lower | `auth_otp_expiry_too_long` |
| Enable leaked-password protection | `auth_hibp_disabled` |
| Set up MFA for your users | `auth_mfa_disabled` |
| Enable CAPTCHA on signup / sign-in / reset | `no_captcha_on_auth` |
| Use a custom SMTP server | `auth_no_custom_smtp` |
| Suitable indices for common query patterns | `rls_unindexed_policy_column` |
| Review rate limits | `auth_rate_limit_missing` |

Deliberately **not** covered, because they are operational rather than detectable from a
project's configuration: PITR and read replicas, load testing, plan tier, organization
owners and org-wide MFA enforcement, and notifying support ahead of traffic surges. Run the
checklist yourself for those — this tool does not replace it.

Supabase also ships Security Advisor and Performance Advisor in the dashboard, which
overlap with parts of this. They are worth running too; this tool adds remediation with
verified rollback, `pg_stat_statements` history forensics, and CI exit codes.

## What's different from the original

| | Original (at fork point) | Here |
|---|---|---|
| Script files | 5 | 32 |
| Check modules | none — one monolithic `audit.js` | 18 modules under `scripts/checks/` |
| Distinct checks emitted | 11 | 54 |
| Tests | none | 36 files |
| Remediation | — | `remediate` with per-finding `BEGIN; … COMMIT;` and a pre-apply snapshot |
| Rollback | — | generated from the ACL **captured before** each fix, never from a template |
| Verification | — | `verify` re-audits after apply; `lab matrix` proves detect → fix → rollback against a real disposable Postgres |
| Production safety | — | two-tier ref protection; a permanent-tier ref cannot be remediated or used as a lab under any flag or env |
| Output contract | ad-hoc JSON | `schema/finding.schema.json`, per-finding `confidence`, evidence you can falsify |

Two behaviours worth calling out because they change what a finding *means*:

- **Rollback restores exactly what was there.** A templated rollback can grant a role privileges it
  never held. Ours reads the live ACL immediately before mutating and restores that.
- **Silence is never a safety claim.** Where a check cannot establish something, it says so — e.g.
  the `SECURITY DEFINER` body analyzer grades an internal auth check `strong` / `weak` / `none`
  rather than emitting nothing and letting absence read as "fine".

## Run it

```bash
git clone https://github.com/fcavalcantirj/secure-my-supa-360
cd secure-my-supa-360
SUPABASE_ACCESS_TOKEN=sbp_xxx node scripts/audit.js YOUR_PROJECT_REF --html report.html
```

Token: `https://supabase.com/dashboard/account/tokens`. Read access is enough for `audit`.

| Subcommand | |
|---|---|
| `audit <ref>` | read-only scan |
| `probe <ref>` | audit + live anonymous probing, so findings are *confirmed* rather than inferred — **opt-in; it signs up a throwaway auth user** |
| `discover [path]` | keyless static scan of a repo |
| `remediate <result.json>` | fix plan; **dry-run by default**, `--apply` mutates |
| `verify <remediation.json>` | re-audit and confirm each fix closed |
| `report <result.json>` | HTML report from a prior result |
| `lab <cmd> <ref>` | seed / teardown / matrix against a **disposable** project |

Exit codes: `0` clean, `2` findings at or above `--fail-on`, `10` auth, `11` network, `12` tool error.

### In CI

```yaml
- name: Audit Supabase
  env:
    SUPABASE_ACCESS_TOKEN: ${{ secrets.SUPABASE_ACCESS_TOKEN }}
    SUPA360_PERMANENT_BLOCKED_REFS: ${{ vars.SUPABASE_PROD_REF }}
  run: |
    git clone --depth 1 https://github.com/fcavalcantirj/secure-my-supa-360 /tmp/supa360
    node /tmp/supa360/scripts/cli.js audit "${{ vars.SUPABASE_PROJECT_REF }}" \
      --fail-on critical --html report.html
```

> `action.yml` is **not yet usable from another repository** — its checkout step takes no
> `repository:` input, so it checks out the caller's repo and then runs `scripts/cli.js`, a path
> only this repo has. Use the `run:` form above.

## Safety gate

The tool cannot know which of your projects is production, so you declare it. Two tiers, **not**
interchangeable:

- `SUPA360_PERMANENT_BLOCKED_REFS` — **production goes here.** Never remediated, never usable as a
  lab; no flag or env combination unblocks it.
- `SUPA360_BLOCKED_REFS` — disposable lab projects. Blocked by default, unblockable with
  `SUPA360_LAB_REF=<same ref>` plus `--i-understand-this-is-destructive`. Production listed here is
  **not** protected.

Either can be declared in a gitignored `.supa360.json` (`permanent_blocked_refs` /
`blocked_refs`), unioned with the env vars. A malformed config is a hard error, never a silent loss
of protection.

## Limits

- Most findings are **inferred** from catalog metadata, not proven by execution. `--probe` proves
  them, and is opt-in because it signs up a real auth user and calls your RPCs.
- Column-grant findings appear only when a role can read a column while lacking table-level
  `SELECT`. A column grant under an existing table grant is a Postgres no-op and is not reported.
- A `weak` auth-check grade means the tool could not establish a guard — not that none exists.
- Storage is audited at bucket and policy level, not per object.
- `supabase_admin`-owned default privileges can't be revoked via SQL; the report names the
  Dashboard toggle.
- Intentionally public RPCs and tables will appear. You decide which are intentional — record that
  in `.supa360.json` suppressions.

## Tests

```bash
node --test test/*.test.js
```

No network. Necessary and not sufficient: the remediation and rollback paths are proven
by `lab matrix` against a real disposable Postgres, because every serious defect this project has
fixed passed a green unit suite at the moment it was wrong.

## License

MIT — see `LICENSE`, which retains both the original copyright (Renzo Madueno) and this fork's.
