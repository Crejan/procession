# p-reserve - specification (draft)

Backups of a host or a workstation into a restic-format repository: runs
them, keeps them fresh, browses and restores them. One library, one daemon
with a command line, one desktop app. Binary `preserve`.

It is a new implementation of what two existing tools do today, each around
the restic command line:

- **Atticus** (macOS, Swift and shell): a menu-bar app with a Secure Enclave
  SSH key and an in-process SSH agent, a scheduler that waits for a good
  moment (idle, network, power), APFS snapshots as the source, retention,
  a snapshot browser, and `.attic` profiles for setup.
- **fundament's host kit** (Linux, Python, `fundament_host.backup_engines`):
  backups of ZFS datasets, trees and dumps, a freshness ledger published as
  metrics, a restore test, and a second engine (`zfs_send`) beside restic.

Both stay as they are. p-reserve does not change them; it replaces them where
and when it has proven itself.

License: MIT OR Apache-2.0.

Status: the three crates exist as skeletons. `p-reserve-core` holds the named
outcomes, the freshness bands, the ledger and the engine trait, with tests.
No engine is implemented, no verb does anything, the desktop app has no window.

## Problem

- **Every question pays for a start.** restic has no long-running mode. Each
  `restic ls` connects, loads the whole repository index and exits. A browser
  on top of that either waits per click or speculates with read-ahead, and
  both were tried in Atticus. The cost was observed there, not measured.
- **Every rule exists more than once.** In Atticus the app and the shell
  scripts each decide what the last success was, what "overdue" means and how
  the daemon is installed; four parsers for "last success" had drifted apart.
  fundament decides the same things a third time in Python.
- **The interface is text.** Both tools classify exit codes, pick lines out of
  a log and match stderr against patterns. A repository library returns
  values instead.

## Scope

- One machine: a workstation with one user, or a host with declared sources.
- Repositories in the restic format, reached over SFTP first.
- Sources: a directory tree; a filesystem snapshot of one (APFS, ZFS); the
  output of a declared dump command.
- Scheduled and manual runs, retention, repository check, restore test,
  listing, browsing, restoring.
- Non-goals: no replacement for `zfs_send` (it stays an engine of
  fundament); no multi-machine dashboard; no fork of restic; no FUSE mount
  in v1; no Windows in v1.

## Architecture

```
preserve CLI ─────┐
preserve-gui ─────┼──> p-reserve.sock ──> preserve serve
(browser, later) ─┘     requests, events    ├─ p-reserve-core
                                            │    ├─ engine (rustic_core): repositories held open
                                            │    ├─ ledger, freshness, policy
                                            │    └─ platform seams (below)
                                            └─ schedule
```

- **The daemon holds repositories open.** Opening one (connecting, loading
  the index) happens once per session; listing a directory after that is a
  lookup. This is what removes the per-click cost, and it is why there is a
  daemon at all rather than a tool that is spawned.
- **Front ends are clients.** The CLI, the desktop app and any later web
  view talk to the daemon over a Unix socket and hold no backup logic. This is
  p-layer's shape (`player serve` behind a socket), and identity can come from
  the socket the same way.
- **The core decides, once.** What a run's outcome is called, which freshness
  band a source is in, which pair last succeeded: one function each, in
  `p-reserve-core`. A front end that needs words for a band maps the band,
  never a timestamp.
- The CLI also works without a running daemon for one-shot verbs on a host
  (`preserve run` from a systemd unit): it opens the repository itself.
  Whether the daemon is then required at all on a host is an open decision.

## Crates

| Crate | Binary | Role |
|---|---|---|
| `p-reserve-core` | - | Library: outcomes, freshness, ledger, the engine trait, later the engine, sources, policy and the platform seams |
| `p-reserve` | `preserve` | The command line and the daemon (`preserve serve`) |
| `p-reserve-gui` | `preserve-gui` | Desktop app: tray icon and a window onto the daemon |

`p-reserve` does not depend on `p-roc`. It follows the workspace conventions:
`--format json` with `schema_version`, configuration in `/etc/p-reserve.toml`
with every key optional, a spec per crate, versioned and tagged on its own.

## Core

Implemented, with tests:

- **`Outcome`**: `ok`, `incomplete`, `deferred`, `no-repository`, `locked`,
  `wrong-password`, `timed-out`, `not-run`, `failed`. The names are
  fundament's (`restic.py`), plus `deferred` for Atticus's "a gate said wait",
  which today is an exit code 0 that only a log line tells from a success.
- **`Freshness`**: `pending`, `fresh`, `overdue`, `stale`, cut at
  `fresh_within` and `stale_after`, with a grace period for a source that
  never succeeded. Only `stale` asks for attention.
- **`Ledger`**: per (source, target) pair the last success, the bytes it
  added, the first attempt of a pair that never succeeded, the last outcome.
  A failure keeps the last success so the pair ages; a deferred run is never
  a success, but it starts the grace period of a pair that has none yet; a
  pair leaves only when it is no longer declared.
- **`Engine`**: an opened repository. So far `snapshots` and `list`.

To come, in the order of "Order of work":

- The engine on `rustic_core`: open, snapshots, list, dump, restore; then
  backup, forget and prune, check.
- Sources: tree, snapshot (through a platform seam), dump command with a
  guard file.
- Policy: retention; the schedule and its gates. Every gate defaults to
  defer on ambiguous input.
- Ledger persistence: the Prometheus textfile fundament publishes today
  (`*_backup_last_success_timestamp_seconds`, `*_backup_last_added_bytes`,
  `*_backup_first_attempt_timestamp_seconds`, labels `source` and `target`),
  written atomically, read back on the next run.
- Restore test: restore one file of a snapshot and compare its SHA-256 with
  the source snapshot it was taken from.

## What the two predecessors require

Taken from the code of both; the library has to cover these before it can
replace either.

From fundament (`backup_engines/`):

- Verbs `run`, `prune`, `check`, `verify`, `snapshots`, `restore`, `mount`,
  `unmount`, `unlock`, `reprovision`; `run`, `prune` and `unlock` only on a
  machine declared the writer.
- Per-source tags (dataset name and `snap:<zfs snapshot>`), an exclude file
  in the source root, an upload limit that applies only inside a window of
  hours, a deadline per source and per operation.
- Its own locks (per repository, per dataset group, shared with `zfs_send`),
  exit code 75 when one is busy.
- The ledger written after every source; a run that ends early fails every
  source it did not reach.
- A check that reads a rotating subset of the data; a restore test that
  rotates through the datasets by quarter.
- `reprovision`: initialises a repository only when it is proven absent,
  restores a seed otherwise.
- SFTP with a key file, a pinned `known_hosts` and strict host key checking;
  the password from a file.

From Atticus:

- A Secure Enclave SSH key served by an in-process agent, with a policy on
  what it signs; optionally a CA-signed certificate. **Not part of
  p-reserve**: this is p-ledge (`crates/p-ledge/SPEC.md`), and p-reserve is
  one of its clients.
- An APFS snapshot as the source, taken and mounted by a root daemon; Full
  Disk Access as a precondition that is checked and explained.
- A scheduler that prefers a quiet moment and forces a run past a maximum
  age; gates for network, power and an unreachable target.
- Automatic retention after a backup; a manual one from the UI.
- Setup from a profile file (`.attic`, TOML) with admin-locked keys.
- A snapshot browser with preview and restore of single items.

Where they disagree:

- **A snapshot with unreadable files.** Atticus counts it as a success
  ("complete with warnings"); fundament counts restic's exit 3 as a failure.
  The core currently follows Atticus (`Outcome::stored_snapshot`). On a
  workstation unreadable files are normal (cloud placeholders, protected
  folders); on a host they are not. This probably wants to be a setting per
  source, not one rule.

## Platforms

The library and the command line are the same code on macOS and Linux. What
differs sits behind seams in the core, one implementation per platform:

| Seam | macOS | Linux |
|---|---|---|
| Source snapshot | APFS local snapshot, mounted read-only | ZFS snapshot; btrfs or LVM later; none (live tree) |
| SSH identity | an agent socket (p-ledge, which holds the Secure Enclave key) | key file; or any agent socket |
| Secrets (repository password) | Keychain | file with mode 0600; Secret Service on a desktop |
| Service manager | launchd (a daemon for snapshots, an agent for the user) | systemd (system unit; user unit on a desktop) |
| Idle, power, network state | IOKit, NWPathMonitor | logind, UPower, NetworkManager or netlink; absent on a server |
| Permissions preflight | Full Disk Access (TCC) | none |
| Tray | menu bar item | StatusNotifierItem (not on every desktop) |
| Updates | app updater | the distribution's packages |

A server has no idle or power state; the gates that read them are simply not
configured there.

p-reserve holds no SSH key and contains no SSH agent. It gives the `ssh` it
starts an SSH agent socket or a key file, and that is all it knows about
keys. On macOS the socket is p-ledge's, which recognises p-reserve by its
code signature and offers it the one key bound to it. Setup stays one flow
in the desktop app (create the key, show the public key for the server, run the first
backup) although two programs are behind it.

The Keychain and TCC have no Rust-native access that matches Apple's own
APIs in every case. The macOS implementations of those seams may be a small
Swift or Objective-C part linked into the daemon, or a helper process. That
is decided when the seam is built, per seam.

### The desktop app

`p-reserve-gui` is the tray icon and one window. Because every view is data
from the daemon, the toolkit decides only how it is drawn. The candidates:

- **Web views served by the daemon, in a thin native window** (wry/tao, or
  Tauri around them). One set of views for macOS, Linux and a browser over
  `ssh -L` to a headless host, as p-layer does it. Costs: a web front end to
  build, and a look that is not native on either platform.
- **A Rust toolkit** (egui, iced, Slint). One code base, no web stack. Costs:
  not native either, weaker accessibility, and no view for a headless host.
- **Native per platform** (SwiftUI on macOS, GTK on Linux). The best fit on
  each. Costs: two apps to write and keep in step, which is the duplication
  this project exists to end. Tolerable only because the app holds no logic.

Recommended: the first, because the host case and the workstation case then
share their views. Not decided; see "Open decisions".

## Repositories and restic

- The repository format is restic's. An existing Atticus or fundament
  repository is opened as it is; nothing is uploaded again.
- rustic does not take restic's locks. Per rustic's FAQ, both programs may
  use one repository, with one exception that matters: `restic prune` while
  rustic backs up is unsafe, because restic deletes at once and relies on a
  lock rustic never takes. `rustic prune` beside a restic backup is listed as
  safe, through rustic's delayed deletion.
- Rule for a migration: **a repository has one program that prunes.** While
  Atticus or fundament still writes to a repository, p-reserve reads it
  (browse, restore, verify) and does not prune. The switch of the writer is
  one step per repository, not a gradual one.
- p-reserve's own daemon, CLI and desktop app all go through one engine in one
  process where they can, so concurrent access from its own front ends is
  mostly not a question for the repository at all.

## Risks, and what is known

Checked against documentation only, in November 2026; none of it tried.

| Question | Known | Open |
|---|---|---|
| SFTP | `rustic_backend` reaches SFTP through OpenDAL, which drives the system `ssh` (the `openssh` crate). Unix only; no password login; host keys through a `known_hosts` strategy. | Whether an agent socket (`SSH_AUTH_SOCK`), a specific key file, a pinned `known_hosts` file and extra `ssh` options can be passed the way both predecessors pass them through `sftp.command`. This decides whether rustic can be the engine. |
| Maturity | `rustic_core` 0.13.0 and `rustic_backend` 0.7.0 (August 2026). rustic's own comparison page lists few tests against restic's coverage. | Its current stability statement; an older README advised against production use. |
| Toolchain | `rustic_backend` 0.6.2 stated a minimum rustc of 1.88; this workspace states 1.85. | The current minimum. p-reserve either raises its own `rust-version` or the workspace's. |
| Fresh snapshot mounts | restic needs `device-id-for-hardlinks`, or every run from a freshly mounted ZFS snapshot rewrites every tree. | rustic's equivalent. |
| macOS metadata | - | Extended attributes, ACLs, flags, resource forks, firmlinks, compared with restic. |
| Index held open | - | Memory of a loaded index for a large repository (the Atticus test repository: about 1.4 million files, 233 index files), and how the daemon learns that another writer changed the repository. |

If SFTP through the predecessors' SSH setups does not work, the fallbacks
are, in order: a backend of our own on `rustic_core`'s backend trait that
spawns `ssh -s sftp` with the exact command line used today; or the restic
command line behind the same `Engine` trait, which keeps the single core and
loses the open index.

## Order of work

1. **SFTP trial on Linux.** The `rustic` binary, then ten lines on
   `rustic_core`, against a copy of a fundament repository: open, list
   snapshots, list a directory, restore a file. With a key file and a pinned
   `known_hosts`.
2. **SFTP trial on macOS** against an Atticus repository through the Atticus
   agent socket.
3. **Read-only engine**: `snapshots`, `list`, `dump`, `restore` behind
   `Engine`; `preserve snapshots`, `ls`, `restore`. Verified with fundament's
   restore test (SHA-256 against the source snapshot) run through p-reserve.
4. **The daemon and the socket**; `ls` answered from an open repository.
   Measure open time and memory.
5. **Ledger persistence and `preserve health`**; fundament's metrics from
   p-reserve's ledger.
6. **Backup of a tree**, then of a snapshot source on each platform; forget
   and prune; check. From here a repository can switch its writer.
7. **Schedule and gates.**
8. **The desktop app**, read-only views first.
9. Platform seams for secrets as each front end needs them; the bound key
   from p-ledge once p-ledge serves one.

Steps 1 and 2 are days, not weeks, and either can end the plan as written.

## Open decisions

- The desktop app's toolkit (above).
- Whether a host runs the daemon or only one-shot verbs from systemd units.
- Privilege on macOS: which part runs as root (snapshots), which as the user
  (Keychain, the agent socket), and how they talk.
- One desktop app for p-reserve and p-ledge, or one each.
- `incomplete` as success or failure, and whether per source.
- The profile format: `.attic` as it is, or a new one that reads `.attic`.
- The name of the product a user sees. `preserve` is the binary; an app may
  carry another.
- Whether p-reserve is published on crates.io like its siblings. The crates
  are `publish = false` until that is decided.
