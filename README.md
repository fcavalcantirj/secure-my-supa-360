# secure-my-supa-360

Audit and harden a Supabase project from your own machine. No SaaS in the middle — the tool
talks only to Supabase's own Management API with a token you supply and never persists.

```
$ supa360 <project-ref> --html report.html
HTML report written to report.html
Findings: 0 critical, 5 high, 2 medium
```

Zero runtime dependencies. Node >= 18. MIT.

---

## Why we built this

**1. Grants and policies drift, and nothing tells you.** A Supabase project accumulates
`SECURITY DEFINER` functions that are technically callable by `anon`, tables where RLS was
enabled but the policy is `USING (true)`, storage buckets that accept anonymous writes, and
default privileges left over from whatever the platform default was the month the project was
created. None of it announces itself. You find out from the audit or from the incident.

**2. RLS correctness and RLS *performance* are the same problem.** Supabase's own
[RLS performance and best practices](https://supabase.com/docs/guides/troubleshooting/rls-performance-and-best-practices-Z5Jjwv)
guide documents patterns that are easy to get wrong and expensive when you do — and every one of
them is mechanically detectable. So we detect them:

| Supabase recommendation | Check here |
|---|---|
| Wrap `auth.uid()` / `auth.jwt()` in a subselect so the optimizer builds an `initPlan` and caches it, instead of re-evaluating per row (their measurements: 179 ms → 9 ms, and 178 s → 12 ms on a complex policy) | `rls_unwrapped_auth_fn` |
| Index the columns your policies filter on when they aren't already a PK or unique (they report >100x on large tables) | `rls_unindexed_policy_column` |
| Always name the role with `TO authenticated` rather than leaving a policy open to `public` | `rls_policy_public_role` |
| Restructure policy joins to compare a row column against fixed join data instead of joining per row | `rls_policy_join` |

A policy that re-evaluates `auth.uid()` for every row is not just slow — under load it is a
denial-of-service surface. Treating it as a security finding rather than a performance nit is a
deliberate choice.

**3. A security tool that is confidently wrong is worse than none.** Findings here carry a
`confidence` (`confirmed` vs `inferred`) and evidence you can use to falsify them. When a check
cannot establish something, it says so explicitly rather than staying silent — silence that reads
as "you're fine" is the failure mode this tool is most careful about.

## What it does

Seven subcommands:

| | |
|---|---|
| `audit <ref>` | read-only scan; 54 checks across RLS, grants, RPC, storage, edge functions, auth config, extensions, realtime, and the Data API surface |
| `probe <ref>` | audit with live anonymous probing, so a finding is *confirmed* rather than inferred — **opt-in, and it signs up a throwaway auth user** |
| `discover [path]` | keyless static scan of a repo (no token needed) |
| `remediate <result.json>` | consume an audit result and print an ordered fix plan; **dry-run by default**, `--apply` mutates |
| `verify <remediation.json>` | re-audit after `--apply` and check each fix actually closed |
| `report <result.json>` | render a shareable HTML report from a prior result |
| `lab <cmd> <ref>` | seed / teardown / full matrix against a **disposable** project, to prove the checks and their rollbacks against a real Postgres |

Every finding ships copy-paste fix SQL. Findings that can be auto-applied are applied inside a
per-finding `BEGIN; … COMMIT;` with a pre-apply state snapshot.

## Install

```bash
git clone https://github.com/fcavalcantirj/secure-my-supa-360
cd secure-my-supa-360
SUPABASE_ACCESS_TOKEN=sbp_xxx node scripts/audit.js YOUR_PROJECT_REF --html report.html
```

Get a token at `https://supabase.com/dashboard/account/tokens`. Read access is sufficient for
`audit`; `remediate --apply` needs write.

## Remediation

`audit` is read-only. `remediate` prints a plan and mutates nothing without `--apply`, which
additionally requires `--yes` (or a TTY confirmation) and a token.

**Safety gate.** The tool cannot know which of your projects is production, so you declare it.
Two tiers, and they are **not** interchangeable:

- `SUPA360_PERMANENT_BLOCKED_REFS` — **put production here.** These refs can never be remediated
  or used as a lab; no flag or environment combination unblocks them.
- `SUPA360_BLOCKED_REFS` — disposable **lab** projects. Blocked by default, but unblockable with
  `SUPA360_LAB_REF=<same ref>` plus `--i-understand-this-is-destructive`. Listing production here
  does **not** protect it.

Declare them via environment, or in a `.supa360.json` at your project root (gitignored — it names
real refs, so never commit it):

```json
{
  "permanent_blocked_refs": ["your-production-ref"],
  "blocked_refs": ["your-disposable-lab-ref"]
}
```

Config and environment are unioned. A malformed `.supa360.json` is a hard error, never a silent
loss of protection.

```
SUPA360_PERMANENT_BLOCKED_REFS=my-prod-ref node scripts/remediate.js result.json --apply --yes --token sbp_xxx
```

Rollback is generated from the ACL captured immediately **before** each fix, not from a template —
so undoing a revoke restores exactly the privileges the role held, and never more.

## Run in CI

```yaml
- name: Audit Supabase
  env:
    SUPABASE_ACCESS_TOKEN: ${{ secrets.SUPABASE_ACCESS_TOKEN }}
    SUPA360_PERMANENT_BLOCKED_REFS: ${{ vars.SUPABASE_PROD_REF }}
  run: |
    git clone --depth 1 https://github.com/fcavalcantirj/secure-my-supa-360 /tmp/supa360
    node /tmp/supa360/scripts/cli.js audit "${{ vars.SUPABASE_PROJECT_REF }}" \
      --fail-on critical --html report.html
- uses: actions/upload-artifact@v4
  if: always()
  with: { name: supabase-security-report, path: report.html }
```

Exit codes: `0` clean, `2` findings at or above `--fail-on`, `10` auth, `11` network, `12` tool error.

> `action.yml` in this repo is **not yet usable from another repository**: its checkout step takes
> no `repository:` input, so it checks out the *caller's* repo and then runs `scripts/cli.js`, a
> path only this repo has. Use the `run:` form above until that is fixed.

## Limits — read these before trusting it

- Most findings are **inferred** from catalog metadata, not proven by execution. `--probe` proves
  them, but it is opt-in precisely because it signs up a real auth user and calls your RPCs.
- Column-grant findings are reported only when a role can read a column while lacking table-level
  `SELECT`. A column grant under an existing table grant is a Postgres no-op and is deliberately
  not reported here — that exposure belongs to the RLS checks.
- The `SECURITY DEFINER` body analyzer grades an internal auth check as `strong` / `weak` / `none`
  by reading the function source. A `weak` grade means the tool could not establish a guard — it is
  not a claim that the function is unguarded.
- Storage is audited at bucket and policy level, not per object.
- `supabase_admin`-owned default privileges cannot be revoked via SQL; the report tells you which
  Dashboard toggle to use.
- Intentionally public RPCs and tables will appear as findings. **You decide which are intentional**
  — use `.supa360.json` suppressions to record that decision.

## Tests

```bash
node --test test/*.test.js
```

738 tests, no network. The unit suite is necessary and not sufficient: correctness of the
remediation and rollback paths is proven by `lab matrix` against a real disposable Postgres,
because every serious defect this project has fixed passed a green unit suite at the moment it
was wrong.

## Credits and license

MIT. This project is a fork of
[Perufitlife/supabase-security-skill](https://github.com/Perufitlife/supabase-security-skill) by
Renzo Madueno, which is the original work and remains under his copyright; see `LICENSE`, which
retains both notices.

This fork reorganized the checks into separate modules, added the remediation and rollback engine
with state-captured (rather than templated) rollback, the disposable-lab harness and matrix, the
two-tier production-ref protection, and the test suite.
