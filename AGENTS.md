# reaper — agent contract

reaper is a disk-reclaim tool an agent can call **instead of re-deriving
safety logic**. You get typed verdicts, a plan artifact that bounds your
blast radius, and honest exit codes. Deletion is permanent; the safety net
is the classifier, not a trash can.

## The loop

```sh
reaper scan <path> --format json     # 1. classify — ZERO mutation, always exit 0
reaper reap --plan <digest>          # 2. rehearse — prints steps, mutates nothing, exit 0
reaper reap --plan <digest> --execute --format json   # 3. the ONLY mutating command
reaper undo <digest>                 # 4. prints recovery commands (never runs them)

reaper update --check                # newer release available? (exit 0 either way)
reaper update                        # install it in place, sha256-verified
```

Rules you can rely on:

- `--execute` **requires** a `plan_digest` from a prior `scan` of the same
  tree. You cannot delete anything a scan didn't show you.
- Every planned directory is identity-bound at scan time and re-verified at
  execution (plus a fresh in-use check). If the tree changed in between,
  that step **refuses and is left in place** — re-scan and re-plan.
- There is no `--force`. Refusals are data, not obstacles.
- `undo` emits shell commands (`cargo build`, `git worktree add …`); running
  them is your decision.

## `reaper scan` — schema `reaper-scan/v1`

```jsonc
{
  "schema_version": "reaper-scan/v1",
  "root": "/home/u/code",
  "candidates": [
    {
      "path": "/home/u/code/svc/target",
      "ecosystem": "rust",
      "detector": "rust-target",
      "safety_class": { "regenerable": { "regenerate_hint": "cargo build" } },
      "size_bytes": 15300000000,
      "idle_days": 21,
      "disposition": { "status": "reapable" }
      // or: { "status": "refused", "reasons": [ { "code": "dirty", "entries": 14 }, … ] }
    }
  ],
  "plan_digest": "sha256:…",   // present iff ≥1 candidate is reapable
  "totals": { "dirs": 105312, "files": 419484, "candidates": 256, "reapable_bytes": 461000000000 }
}
```

`--format ndjson` emits one candidate object per line, then one final line
with `schema_version` + `totals` + `plan_digest` — consume incrementally on
huge trees.

Narrowing predicates (they shrink the report AND the plan):
`--ecosystem rust,node` · `--min-size 1G` · `--min-idle-days 7` ·
`--exclude '<glob>'` (never reaped, beats everything) · `--include-caches`.

### Refusal codes (`disposition.reasons[].code`)

| code | meaning | extra fields |
|---|---|---|
| `dirty` | uncommitted or untracked work in a worktree | `entries` |
| `unpushed_commits` | commits no remote holds | `count` |
| `locked` | `git worktree lock` is set | `note` |
| `detached` | detached HEAD; its commits die with the dir | `unreachable_commits` |
| `live_process` | a process has cwd/open file inside | `pids` |
| `active_build` | a build is writing right now | `pids` |
| `cross_device` | on a different mount than the scan root | |
| `cloud_backed` | cloud-sync placeholder; deleting triggers downloads | |
| `protected` | matches an `--exclude` glob | `pattern` |
| `caches_excluded` | shared package cache without `--include-caches` | |
| `too_recent` | younger than the idle floor | `idle_days`, `min_idle_days` |
| `too_small` | below `--min-size` | `size_bytes`, `min_size_bytes` |
| `unknown` | a fact could not be established — fail-closed | `what` |

Treat `unknown` as "reaper couldn't prove safety here", not as an error.

## `reaper reap --execute` — schema `reaper-reap/v1`

```jsonc
{
  "schema_version": "reaper-reap/v1",
  "plan_digest": "sha256:…",
  "executed": true,
  "outcomes": [
    { "outcome": "reaped",  "path": "…/target", "freed_bytes": 15300000000,
      "recover": "cargo build" },
    { "outcome": "refused", "path": "…/node_modules",
      "why": "identity drifted since planning (dev/ino/mtime mismatch) — re-scan" }
  ],
  "freed_bytes": 15300000000
}
```

`--plan` accepts the full digest or any unique prefix.

## Exit codes

| code | meaning |
|---|---|
| `0` | clean — including every dry-run and every all-refused scan (a refusal is the system *working*) |
| `1` | one or more `--execute` steps failed or refused |
| `2` | usage/state error: unknown plan digest, another reaper holds the execute lock, unwritable state |

## Environment

- `REAPER_STATE_DIR` — where plans, the reap journal, and the execute lock
  live (default: the platform state dir). Point this somewhere private if
  you run parallel agents; the execute lock is per state dir.
- `reaper rules --format json` — the active detection ruleset, for audit.
- `reaper update --check` — exits 0 and reports whether a newer release
  exists; `reaper update` installs it in place (sha256-verified). Exit 2 on
  network or verification failure; the binary is never left half-written.

## Known limits (v0.1)

- One `--execute` at a time per state dir (exclusive lock).
- `--max-bytes` / `--max-count` backstop caps are not implemented yet; bound
  blast radius with the narrowing predicates above.
- On Windows, scan-time in-use detection samples open files; the delete-time
  check is authoritative (a held directory refuses and is left in place).
