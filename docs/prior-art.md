# Prior art — the landscape reaper is built on

A survey of open-source filesystem-bloat / disk-usage / project-cleaner tools,
the crates worth building on, and the gap reaper fills. Sources are GitHub repos
(URLs at the end).

## 1. The tools

| Tool | Lang | Stars | Activity | What it does |
|---|---|---|---|---|
| **kondo** (`tbillington/kondo`) | Rust | ~2.3k | active (v0.9, Jan 2026) | Cleans build/dep dirs across 20+ project types; CLI + GUI + TUI |
| **dua-cli** (`Byron/dua-cli`) | Rust | ~6k | very active (v2.37, Jun 2026) | Interactive disk-usage analyzer; marking + multi-stage deletion |
| **dust** (`bootandy/dust`) | Rust | ~12k | active | `du` rewrite; colored tree view; **no deletion** (analyzer only) |
| **diskonaut** (`imsnif/diskonaut`) | Rust | ~3.1k | **dormant since 2020** | Treemap navigator; deletes + tracks freed space; explore-while-scanning |
| **gdu** (`dundee/gdu`) | Go | ~5.8k | active | Fastest DU TUI; parallel goroutines; interactive delete |
| **ncdu** (`yorhel/ncdu`) | C→Zig | — | active (v2.6) | The baseline DU-TUI UX everyone imitates |
| **cargo-sweep** (`holmgr/cargo-sweep`) | Rust | ~1k | **unmaintained** | Rust-only `target/` pruning by time/toolchain/size |
| **cargo-clean-all** (`dnlmlr/cargo-clean-all`) | Rust | — | active | Recursive Rust target cleaner; TUI + filters |
| **projectable** (`dzfrias/projectable`) | Rust | ~0.5k | active | Project-oriented file-manager TUI (UX reference) |
| **gargantua** (`inceptyon-labs/gargantua`) | Rust/Swift | new | active | macOS cleaner with **YAML-driven safety rules** + risk classification |

### kondo — the closest prior art
- **Detection:** hardcoded per-language `ProjectType` enum (Cargo→`target`,
  Node→`node_modules`, Maven/Gradle, Python, .NET, Unity…). Marker → artifact
  mapping, **not** config-driven.
- **Safety:** self-described as *"essentially `rm -rf` with a prompt."* Has
  `--dry-run`, a confirmation, and an `--older 3M` age filter. **No
  git-awareness** — README's only guidance is "always have a backup." The key
  weakness reaper fixes.
- **Take:** age filter; per-project reclaimable size shown before cleaning;
  CLI/GUI/TUI parity. **Avoid:** hardcoded enum (needs a PR per ecosystem); no
  git safety.

### dua-cli — the best deletion-safety UX
- **Scanning:** `jwalk` (parallel, rayon). *"Thanks to jwalk, all there was left
  to do is write a CLI."*
- **Safety:** **multi-stage marking** — tag entries, then a separate deletion
  confirmation; "great care taken to prevent accidental deletions."
- **Take:** mark-then-commit flow; `?` help overlay; Esc-to-parent (not quit);
  config-file keybinds.

### dust — tree rendering reference
- Colored ASCII bars; a grey-shade gradient encodes parent-child membership;
  output capped to terminal height. Analyzer only. **Take:** compact,
  information-dense rendering.

### diskonaut — explore-while-scanning + freed counter
- Indexes to memory and lets you browse *during* the scan; a session freed-space
  counter; treemap layout. Dormant since 2020. **Take:** the live-scan browsing
  and the freed-space counter; **avoid** the dormancy trap (keep detection as
  data so the tool doesn't rot when a new ecosystem appears).

### gdu — the performance bar
- Go + goroutines. Cold-cache ~4.7 s vs ncdu 33 s vs `du` 30 s; warm ~466 ms.
  A **constant-memory** mode tracks only top-level totals. `--no-delete` global
  safety switch. **Take:** constant-memory top-level mode; hardlink dedup;
  `--no-delete`; the sub-5 s cold-scan bar.

### ncdu — UX baseline
- Zig rewrite added multi-thread scan (`-t8`) and out-of-core browsing of trees
  too big for RAM. **Take:** vim nav, in-place delete-with-confirm, sort toggles,
  the out-of-core idea for huge trees.

### cargo-sweep / cargo-clean-all — staleness heuristics (Rust-specific; ideas generalize)
- **cargo-sweep:** clean `target/` by age-in-days, **toolchain match** (delete
  artifacts not built by an installed toolchain), size ceiling, timestamp marker.
- **cargo-clean-all:** recursive discovery; `--keep-days` (mtime), `--keep-size`
  (only projects with freeable > threshold), `--keep-executable` (salvage built
  binaries before wipe), `--threads`, TUI + dry-run.
- **Take (generalized to per-rule predicates):** "last-used > N days,"
  "freeable > N GB," salvage-executables, toolchain-staleness.

### projectable / gargantua — config & risk models
- **projectable:** ratatui + crossterm; **TOML config**; vim keys; mark system;
  gitignore-respecting; live updates. UX reference.
- **gargantua:** the only surveyed tool with a **public, versioned ruleset** +
  **risk classification** ("why this is safe/risky") + user-controlled removal.
  macOS-system-cleaner domain, not git-aware. **Take:** rules-as-data + risk-tier
  + explainability.

## 2. Crate choices

### Parallel filesystem walking
| Crate | Model | Note |
|---|---|---|
| **jwalk** (`Byron/jwalk`) | rayon parallel, streamed+sorted, `process_read_dir` closure to prune subtrees | **Portable baseline.** The per-dir closure enables prune-on-marker + inline metadata; same author as dua-cli. |
| **ignore** (ripgrep) | `WalkParallel`, gitignore-aware | Good, but gitignore-awareness is a *trap* here — `target/`/`node_modules/` are gitignored; must be walked with ignores **off**. |
| **walkdir** | single-threaded | Too slow for a fast scanner. |

**Platform fast-paths are a leaf behind a one-directory-wide `DirReader` port**
(the parallel walk + prune live once, portably, above it — see `SPEC.md` §6):
- **macOS: `getattrlistbulk(2)`** — name + type + size + mtime for many entries
  in one syscall; eliminates per-entry `stat`. The biggest Darwin win.
- **Windows: `NtQueryDirectoryFile` / `FindFirstFileEx`+`LARGE_FETCH`** — size +
  timestamps inline in the enumeration; like macOS, no per-file attribute call.
- **Linux: `getdents64(2)` + `d_type`, then `statx(2)` via `io_uring`** —
  `d_type` avoids a type `stat`; io_uring pipelines size/mtime. Linux is the one
  platform needing a size fill-pass.
- **`StdDirReader`** (`std::fs`) — the portable floor that works on all three
  OSes from day 1; fast leaves are additive, chosen at runtime with fallback.

**The core mechanic:** detect a marker + its artifact dir in one pass, aggregate
that subtree, then **skip descending into it** — `O(all files)` → `O(dirs until
artifact)`. Backends declare a `Caps { size, mtime, ino }` so the port is
designed to the *weakest common capability*, never cornered by the richest
backend's shape.

### Sizing
- Accumulate `st_blocks × 512` during the walk (on-disk, not apparent). Dedup
  hardlinks via a `(dev, inode)` set. Parallel sum via rayon reductions.

### TUI
- **ratatui + crossterm.** Immediate-mode (redraw each tick) is ideal for a
  live-updating scan; the dominant, actively-maintained stack. Rejected
  `cursive` (retained-mode, callback-oriented — awkward for streaming).

### Concurrency
- **rayon** walker → **crossbeam-channel** → main-thread crossterm loop that
  drains + redraws on a ~30–60 ms tick. **No tokio** — filesystem + subprocess
  work is CPU/IO-bound, not connection-bound; async would add an unused runtime.

## 3. The gap reaper fills

Two properties are individually common but **never combined**:

1. **Language-agnostic reclaimable-dir detection via a user-editable ruleset.**
   kondo/cargo-sweep/cargo-clean-all all hardcode targets (an enum, or
   Rust-only). The only rules-as-data cleaner found (gargantua) is a macOS
   *system* cleaner, not project/build-artifact-oriented, not cross-platform.
2. **Bloat scanning *with* git-safety.** Every disk tool deletes on filesystem
   facts alone; git-safety lives only in separate worktree-prune tooling. No tool
   scans bloat *and* refuses a dir whose enclosing worktree is dirty / has
   unpushed commits / is locked / is in use.

**Conclusion:** the intersection of (fast, language-agnostic bloat scan) ×
(config-driven detection) × (git-safety fail-closed gate) × (permanent reclaim) ×
(co-equal TUI + agent-JSON) is **unserved**. kondo is closest but is hardcoded
and git-blind; dua has the best safety-UX but no project semantics; the cargo
tools have the best staleness heuristics but are single-language. reaper is that
intersection.

## 4. URLs

github.com/tbillington/kondo · github.com/Byron/dua-cli · github.com/bootandy/dust ·
github.com/imsnif/diskonaut · github.com/dundee/gdu · github.com/yorhel/ncdu ·
github.com/holmgr/cargo-sweep · github.com/dnlmlr/cargo-clean-all ·
github.com/dzfrias/projectable · github.com/inceptyon-labs/gargantua ·
github.com/Byron/jwalk · github.com/ratatui/ratatui · github.com/gyscos/cursive
