# reaper 💀

**Your disk is full of things a rebuild would bring back.** `target/`,
`node_modules/`, `.venv/`, Gradle caches, stale git worktrees — tens to
hundreds of gigabytes of it. Deleting it by hand is a bespoke survey of your
machine plus a small gamble that nothing precious is inside.

**reaper does the survey and removes the gamble.** It scans your tree,
classifies every directory as *reclaimable* or *refused-with-a-reason*, and
reclaims only what it can prove is safe — from a keyboard TUI or a JSON CLI.

[![ci](https://github.com/benelser/reaper/actions/workflows/ci.yml/badge.svg)](https://github.com/benelser/reaper/actions/workflows/ci.yml)
[![release](https://img.shields.io/github/v/release/benelser/reaper?include_prereleases)](https://github.com/benelser/reaper/releases)
![platforms](https://img.shields.io/badge/platforms-macOS%20·%20Linux%20·%20Windows-blue)
![license](https://img.shields.io/badge/license-MIT-green)

![reaper demo — scan, mark, confirm, reclaim](assets/demo.gif)

## Install

**macOS / Linux**

```sh
curl -fsSL https://raw.githubusercontent.com/benelser/reaper/main/install.sh | sh
```

**Windows (PowerShell)**

```powershell
irm https://raw.githubusercontent.com/benelser/reaper/main/install.ps1 | iex
```

One line, on your `PATH`, done — and staying current is `reaper update`
(checksum-verified, swaps the binary in place). Both installers and the
updater run end-to-end in CI on every push and against every published
release. From source: `cargo install --git https://github.com/benelser/reaper reaper`.

## Use it

```sh
reaper                      # interactive: browse this project's bloat, reap what you mark
reaper ~/code               # interactive: sweep everything under ~/code

reaper update               # get the newest reaper — verified, swapped in place

reaper scan ~ --format json           # script it: every verdict as JSON, deletes nothing
reaper scan ~ --ecosystem rust --min-size 1G   # narrow to big Rust targets
reaper reap --plan sha256:… --execute # delete exactly what that scan showed — nothing else
reaper undo sha256:…                  # print the commands that regenerate what you reaped
```

Building on top of reaper — or letting an agent drive it? The full typed
contract (schemas, refusal codes, exit codes, invariants) is in
[AGENTS.md](AGENTS.md).

In the TUI: `space` marks, `a` marks everything reapable, `x` opens the
confirm, a typed `y` commits, `/` filters, `q` quits. Deletion is permanent —
that's why the space comes back instantly — and refused rows can't be marked.

## How it decides

Most cleanup tools assume a directory is safe unless something looks wrong.
**reaper inverts the heuristic — nothing is safe until everything is proven:**

1. **Only the regenerable is ever a candidate.** A directory enters the list
   only by matching a rule that knows how it comes back — `cargo build`,
   `npm install`, a git branch that survives the worktree. Unique data is
   never on the table to begin with.
2. **Safe is proven, not assumed.** Every candidate must affirmatively pass
   every check: git state clean and pushed, nobody using it, no build writing
   into it, on the same disk, not a cloud placeholder, old enough that you've
   moved on. One failed check refuses. One *unanswerable* check — a
   permission error, an unreadable repo — also refuses: **doubt counts as
   danger.**
3. **The proof is re-taken at the moment of deletion.** Between "you looked"
   and "it deletes," trees change. reaper re-verifies identity and liveness
   per directory right before removal, and if anything shifted, it refuses
   and asks you to re-scan.

That's the whole philosophy. The refusal reasons you see on screen —
`dirty(14)`, `unpushed(3)`, `building`, `locked`, `fresh(0d<3d)` — are just
rule 2 talking. And there is no `--force` flag to argue with it.

## Fast

Measured, not vibes — the performance suite runs on every merge:

| | |
|---|---|
| Traversal engine vs `jwalk` (a fast parallel walker) | **1.2–1.4× faster**, on macOS, Linux, and Windows |
| Matching a build dir vs walking into it | **13–28× faster** — a 15 GB `target/` is one candidate, zero descents |
| Real dev tree: 105k dirs, ~1.4M files, 256 candidates | surveyed **and fully sized (430 GB)** in about a minute |
| Perceived delete | **instant** — the path vanishes atomically; space drains back in the background |

Under the hood: native bulk directory syscalls per OS, a work-stealing
parallel walker, no subprocesses.

## What it detects

27 rules out of the box: Rust, Node (+ `.next`/`.turbo`/`.nuxt`), Python
(venvs, `__pycache__`, `.tox`, `.mypy_cache`, `.pytest_cache`), Gradle,
Maven, .NET, Go, Xcode, CocoaPods, Zig, Dart, Elixir, PHP, **git
worktrees**, and a [`CACHEDIR.TAG`](https://bford.info/cachedir/) catch-all
that finds caches nobody wrote a rule for — on the first real machine it ran
on, it surfaced 59 GB from a build system no rule had named. Every rule is a data row in
[`rules.toml`](crates/reaper-core/rules.toml), so adding an ecosystem is an
edit, not a fork.

> **Status: v0.1 alpha.** The scan → plan → reap → recover loop works and is
> tested on macOS, Linux, and Windows. Treat `--execute` with the respect a
> permanent delete deserves.

## License

MIT
