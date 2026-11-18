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

Status: `p-reserve-core` holds the named outcomes, the freshness bands, the
ledger with its Prometheus textfile, the health rule and the engine trait, with
tests. `preserve health` works from the ledger file. No engine is implemented,
no other verb does anything, the desktop app has no window.

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
- **Jobs belong to the daemon, not to a connection.** Closing a connection
  cancels only what was asked as bound to it: browsing, a preview or dump for
  display, subscriptions. A backup, a prune, a check and a restore are jobs:
  each has an identifier, goes on when the connection that started it closes, is
  cancelled only by an explicit message naming it, and a front end that connects
  later lists the running jobs and attaches to their events. The protocol is
  `proposals/socket-protocol.md` (accepted by the designer as the protocol to
  build on). Only the daemon's own uid is served. One thing about a job is
  persisted: a start marker, written before a writing job begins and removed
  with the ledger entry; a marker left behind becomes, at the next start, a
  `failed` entry with the cause `interrupted` (`p_reserve_core::marker`).
  `cancelled` means no snapshot was written and never touches the ledger; a
  stored snapshot always does.
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
  added, how many files it could not read, the first attempt of a pair that
  never succeeded, the last outcome.
  A failure keeps the last success so the pair ages; a deferred run is never
  a success, but it starts the grace period of a pair that has none yet; a
  pair leaves only when it is no longer declared.
- **`Engine`**: an opened repository. So far `snapshots` and `list`.
- **`Run`**: how one run of one pair ended. A snapshot with unreadable files
  is `incomplete`, never `ok`, and `Run::stored` is the one place that says so;
  the run over several sources is the worst of its sources' outcomes
  (`Outcome::worst`; the order among the failures is a proposal, only
  "`ok` < `deferred` < `incomplete` < any failure" is settled).
- **`Textfile`**: the ledger as the Prometheus textfile fundament publishes
  today (its three families under a configurable prefix, `preserve_` by
  default) plus `backup_last_unreadable_files` and
  `backup_last_outcome{outcome=...}`, so that `health` can read everything
  from the file. Written atomically with an explicit mode (0644, whatever the
  umask), read back strictly: a malformed file is an error and never an empty
  ledger (which would read as stale everywhere); a missing file is the first
  run.
- **`marker`**: the start marker of a writing job (see "Architecture", jobs).
  The ledger also records when the last run of any outcome was recorded
  (`backup_last_attempt_timestamp_seconds`) and an optional cause (`interrupted`,
  a label of `backup_last_outcome`).
- **`health`**: the level of every declared pair, from one rule (below).

### Health

`preserve health` reads the ledger file and the configuration, needs no
daemon, and its exit code is for a monitor:

| Code | Meaning |
|---|---|
| 0 | ok: every pair is fresh and its last run was clean |
| 1 | warning: some pair is overdue, its last run was `incomplete` or failed, or its last snapshot could not read some files |
| 2 | critical: some pair is stale, or declared and never seen |
| 3 | unknown: the ledger or the configuration could not be read or understood; nothing is said about the pairs |
| 4 | usage error |

No code has two meanings. Per pair, the level is the loudest of: the
freshness band (`overdue` warning, `stale` critical); the last outcome
(`incomplete` and every failure are warnings, `ok` and `deferred` are not);
files the last successful snapshot could not read (any: warning). So an
`incomplete` snapshot counts for freshness and is never shown as `ok`; a
failure keeps the pair a warning until its age makes it critical, and
repeating a failure raises nothing. **Only a success moves freshness.** A pair
that never succeeded is pending for its grace period, counted from its first
attempt, and critical after it, however many attempts, failed or deferred, come
later and however recent the last one is; it is never fresh and never "up to
date". A declared pair the ledger has not seen is critical. Without declared
pairs, every pair in the ledger is reported.

Limits: `fresh_within` 26 hours, `stale_after` 72 hours, `first_run_grace` one
hour. They are provisional and **assume a daily schedule**; the file's
`[freshness]` changes them for every pair, and a `[[pair]]` sets its own (a
weekly pair is not judged by a daily one).

The configuration (`/etc/p-reserve.toml`, TOML because a person writes it) is
read as strictly as the JSON settings files: a regular file, owned by root or
the running user (`p_act::settings::check_owner_and_mode`, not a copy), no group
or other write bit, an unknown key refused, a key given twice refused, at most
1 MiB, and no error text carries a value from the file. A repository password is
never in it: a path to a 0600 file, or the key store.

The ledger file (mode 0644, whatever the umask, readable by the metrics
exporter) holds what a local user may read: source and target names, outcomes,
times, byte and file counts. A configured name of a source or a target is a plain
word, `[a-z0-9][a-z0-9._-]{0,63}`: no slash, no upper case, not `.` or `..`. That
is what goes into the ledger, the metrics' labels and the socket's messages; the
path it stands for stays in the configuration. A configuration with a name outside
the class is refused at load, with the name (cut, printable) and the rule. It holds no
repository address, no credential, no path from inside a home directory.

### Reading a repository

Strings from outside (a file name in a snapshot, a host, a path, a tag) are
shown through `p_ermit::text`, never raw: a control character (C1 included), a
bidirectional mark or a byte that is not UTF-8 is written as visible literal
text (`\u{202e}`, `\x{ff}`), reversibly, and a record that holds one says
`"escaped": true`. Each field has a bound on the escaped text (a name 1024
characters, a path 8192, a host or a tag 512; proposed) and a record that was
cut says `"clipped": true`.

Two facts about what the engine does, not about our code:

1. **A name that is not UTF-8 is carried as bytes** (`Node.name` is a byte
   string from the engine to the output, never `to_string_lossy`) and shown
   escaped, so two different names never show alike; `restore` writes the real
   name, bytes and all. A file is named to `dump`/`restore` by a `&str` path, so
   a file whose name is not UTF-8 is reached by restoring its directory.
2. **A snapshot written by restic after the engine opened the repository is
   listed at once and its data is unreadable until the repository is reopened,
   never wrong bytes** (`failed`, "Tree ID ... not found in index"). The rule
   that follows: the daemon, on that failure, reopens the repository **once**
   and retries, and reports the failure if it fails again. The one-shot CLI
   opens the repository once per invocation, so it only meets this when a writer
   races it within one run; it does not retry, reports `failed` and the operator
   runs it again.

The engine's own words (rustic quotes paths and repository data) are never in
the JSON: an `error` record has the outcome (a closed code) and nothing else;
the text goes to stderr, escaped and cut at 512 characters. The ledger and the
markers are preserve's own state files and are read strictly: a name outside
`[a-z0-9][a-z0-9._-]{0,63}` refuses the whole file (the line, never the
value), and nothing is written whose names break it. A ledger of another tool
(fundament's names are dataset paths such as `tank/home`) is not read; taking
one over would be an explicit, one-time import run knowingly by an operator,
which is not built.

The engine is a cargo feature, `engine-rustic` of `p-reserve` (and of
`p-reserve-core`), off by default: `rustic_core` and `rustic_backend` are about
500 crates and minutes of build. A build without it still has everything else
(core, ledger, health, freshness, configuration); `snapshots`, `ls` and
`restore` then fail with the outcome `not-run` and the words "this build has no
repository engine", exit 3, and `preserve catalog` does not mark them
implemented. Test it with `cargo test -p p-reserve --features engine-rustic`.

`preserve snapshots <target>`, `preserve ls <target> <snapshot> [path]` and
`preserve restore <target> <snapshot> <path> --to <destination>` open the
repository themselves (no daemon), through `RusticEngine` on `rustic_core`;
`--format json` carries `schema_version` and one record type per verb
(`snapshots`, `ls`, `restore`, and `error` with the outcome's name). Nothing
here writes to a repository. A snapshot is `latest`, an id or a prefix of one.
A target is a `[[target]]` of the configuration: `name`, `repository` (a local
path, or `opendal:sftp`, `rest:...`), `password_file`, optional `options`.
The password is only ever in the file named by `password_file`, which must be a
regular file owned by root or the running user with no group or other
permission; it is never an argument, an environment variable or in the
configuration. A restore never overwrites or deletes: the destination is
absolute and does not exist (a file) or does not exist or is empty (a
directory, whose contents are restored into it).

| Code | Meaning (snapshots, ls, restore) |
|---|---|
| 0 | done |
| 3 | failed: the outcome is named (`no-repository`, `wrong-password`, `failed`, or `not-run` for a configuration or password file that was refused) |
| 4 | usage error |

To come, in the order of "Order of work":

- The engine on `rustic_core`: open, snapshots, list, dump, restore; then
  backup, forget and prune, check.
- Sources: tree, snapshot (through a platform seam), dump command with a
  guard file.
- Policy: retention; the schedule and its gates. Every gate defaults to
  defer on ambiguous input.
- Restore test: restore one file of a snapshot and compare its SHA-256 with
  the source snapshot it was taken from.

## What the two predecessors require

Taken from the code of both; the library has to cover these before it can
replace either.

From fundament (`backup_engines/`):

- Verbs `run`, `prune`, `check`, `verify`, `snapshots`, `restore`, `mount`,
  `unmount`, `unlock`, `reprovision`; `run`, `prune` and `unlock` only on a
  machine declared the writer. p-reserve keeps `run`, `prune` (which forgets
  by the retention policy, then prunes; `forget` is not a verb), `check`,
  `verify`, `snapshots`, `restore`, `reprovision` (initialise only when the
  repository is proven absent), and adds `ls`, `health`, `status`, `serve`.
  `mount` and `unmount` are not in v1 (no FUSE). `unlock` is dropped while the
  engine is rustic, which takes no locks.
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

- **A run that began and never ended** is a `failed` ledger entry with the
  cause `interrupted`, found from the start marker at the next start; it keeps
  the last success, so the pair ages, and `health` reports it as a warning.
- **A snapshot with unreadable files.** Atticus counts it as a success
  ("complete with warnings"); fundament counts restic's exit 3 as a failure.
  Decided: it counts for freshness (a snapshot was made), is never shown as
  `ok`, is a warning in `health`, is recorded per source with the count of
  what could not be read, a run's outcome is the worst of its sources', and
  repeating it does not escalate it. One rule, not a setting per source.

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

**Superseded for macOS.** The recommendation of the first candidate (web views) is
withdrawn there: Atticus's SwiftUI front end becomes preserve's Mac front end, a
client of the socket, and only after two conditions hold: the logic still in its
views and view models has moved into the daemon (first: the snapshot browser,
which drove the engine class directly; the exclude store and the rules of the
backup pane; the prune marker a view model wrote), and the protocol offers what
section 8.5 of `crates/p-ledge/proposals/stage2-mac.md` lists (met or answered
point by point in `proposals/socket-protocol.md`). Nothing is copied from Atticus
yet: the licence between Atticus and procession is the owner's decision.
`p-reserve-gui` gets no code. The Linux desktop stays open, and the web-view
candidate stays the one that also serves a headless host.

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
- `unlock` does not exist while the engine is rustic, which takes no restic
  locks; a lock left by a restic client stays that client's to clear. The
  hazard is the other direction: a restic client's `prune` beside p-reserve's
  backup is unsafe, because restic deletes at once and relies on the lock
  p-reserve never takes.
- p-reserve's own daemon, CLI and desktop app all go through one engine in one
  process where they can, so concurrent access from its own front ends is
  mostly not a question for the repository at all.

## Risks, and what is known

Checked against documentation in November 2026, and against the sources of
`rustic_backend`, OpenDAL and `openssh`; the SFTP row also against a run by
the owner on 2026-11-18 (`trial/REPORT.md`). The rest was not tried.

| Question | Known | Open |
|---|---|---|
| SFTP | `rustic_backend` reaches SFTP through OpenDAL, which drives the system `ssh` (the `openssh` crate). Unix only; no password login; host keys through a `known_hosts` strategy. | Run: a key file with strict checking works; an agent works with `key` naming the public half (`SSH_AUTH_SOCK` is inherited). Read: OpenDAL's sftp takes only `endpoint`, `root`, `user`, `key`, `known_hosts_strategy`. **A pinned `known_hosts` file cannot be passed**: strict checking fails unless the host key is in the real `~/.ssh/known_hosts` (run, A1/A2); no `-F`, no extra `-o`. Open: open time and memory (the run did not finish), and whether to pin through the real `known_hosts` or write a backend of our own that spawns `ssh -s sftp` (below). |
| Maturity | `rustic_core` 0.13.0 and `rustic_backend` 0.7.0 (August 2026). rustic's own comparison page lists few tests against restic's coverage. | Its current stability statement; an older README advised against production use. |
| Toolchain | `rustic_core` and `rustic_backend` state a minimum rustc of 1.91. | Decided: the workspace has one `rust-version` for all crates, raised to what its dependencies need (1.91). The dependency closure of `rustic_core` 0.14.0 and `rustic_backend` 0.8.0 (default features, OpenDAL included) builds offline from the unpacked registry; adding it took 4 min 17 s of a debug build on a loaded machine (about 700 crates in all), and a test build of the three p-reserve crates with optimised dependencies about 30 min on the same machine. Debug-build dependencies make the key derivation and the index load about 30 times slower (140 s against 4 s): the workspace wants `[profile.dev.package."*"] opt-level = 2` (requested from the orchestrator). |
| Fresh snapshot mounts | restic needs `device-id-for-hardlinks`, or every run from a freshly mounted ZFS snapshot rewrites every tree. | Read from the source, not run: rustic's `set_devid` defaults to `hardlink` (the device id only for hardlinks), and its parent match compares size, mtime, ctime and inode, not the device. Run against a real fresh mount. |
| macOS metadata | - | Extended attributes, ACLs, flags, resource forks, firmlinks, compared with restic. |
| Index held open | Measured once, release build, a tiny local repository, on a machine with a load average of about 145: init and one snapshot 6.3 s, open and load the index 4.3 s (a debug build: 140 s, nearly all in dependencies, see the Toolchain row). Memory not measured. Observed with a repository written by restic 0.19.0 (local, temporary): the engine lists, reads and restores it with matching SHA-256; opening takes no lock and changes nothing; while a `restic backup` holds its lock the repository opens and reads normally (rustic neither waits nor refuses); a snapshot written after the open is listed at once (the list is read from the repository each time) but its data is not in the loaded index, so reading it fails with `failed` ("Tree ID ... not found in index") until the repository is opened again: the daemon must reopen when that happens, or when it learns of a new snapshot. | Memory of a loaded index for a large repository (the Atticus test repository: about 1.4 million files, 233 index files), and how the daemon learns that another writer changed the repository. |

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
   (Built and tested against local repositories in a temporary directory, one
   written by rustic and one by restic 0.19.0, with the SHA-256 restore test
   against a source tree; not yet against SFTP. The engine tests are not in the
   default run: `cargo test -p p-reserve-core --features testing --offline --test engine`
   and `cargo test -p p-reserve --features engine-rustic --offline`.)
4. **The daemon and the socket**; `ls` answered from an open repository.
   Measure open time and memory.
5. **Ledger persistence and `preserve health`**; fundament's metrics from
   p-reserve's ledger. (Done, in `p-reserve-core` and `preserve health`.)
6. **Backup of a tree**, then of a snapshot source on each platform; forget
   and prune; check. From here a repository can switch its writer.
7. **Schedule and gates.**
8. **The desktop app**, read-only views first.
9. Platform seams for secrets as each front end needs them; the bound key
   from p-ledge once p-ledge serves one.

Steps 1 and 2 are days, not weeks, and either can end the plan as written.

## Open decisions

- The desktop app's toolkit (above). Provisionally, on macOS, the SwiftUI
  front end of Atticus as a client of the socket; no Rust toolkit is chosen;
  the Linux desktop is decided later; `p-reserve-gui` has no code.
- Decided: a host runs one-shot verbs from systemd timers; the daemon is for
  where something stays open. The CLI works fully without a daemon.
- Privilege on macOS: which part runs as root (snapshots), which as the user
  (Keychain, the agent socket), and how they talk.
- One desktop app for p-reserve and p-ledge, or one each.
- The profile format: `.attic` as it is, or a new one that reads `.attic`.
- The name of the product a user sees. `preserve` is the binary; an app may
  carry another.
- Whether p-reserve is published on crates.io like its siblings. The crates
  are `publish = false` until that is decided.
