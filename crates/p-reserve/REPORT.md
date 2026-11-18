# p-reserve report

## Unit 1: merge, script fix, trial record (done)
- `integration` (8d1980e) merged into `agent/p-reserve` (clean; brings rust-version 1.91 and p-act).
- `trial/run-trial.sh`: C builds first as a visible step, runs from the built binary (no `tail`),
  prints progress lines; `sh run-trial.sh c` runs C alone against the sshd the script starts,
  `build` only builds. INT/TERM/HUP/exit all run one cleanup (agent, the one known_hosts line the
  script added, leftover `ssh-connection` masters for 127.0.0.1, sshd) and print three checks
  (`grep -c '\[127.0.0.1\]:22222' ~/.ssh/known_hosts` = 0; `pgrep -fl 'p-reserve-trial|ssh-connection'`
  empty; `lsof -nP -iTCP:22222 -sTCP:LISTEN` empty). The script prints the versions to read off.
- `trial/REPORT.md`: the owner's run of 2026-11-18 recorded as his run, with what to read off his machine.
- Not verified: the script has still never run (the sandbox cannot bind a port); only `sh -n`.

## Unit 2: the transport-independent core (done)
What exists (`p-reserve-core`, `p-reserve`):
- `Outcome`: `name()`/`from_name()`, `severity()` (distinct per outcome), `Outcome::worst`, `level()`;
  `Level` (ok, warning, critical; `exit_code()` 0/1/2).
- `Run` (`stored(added, unreadable)` is `Incomplete` when unreadable > 0, never `Ok`; `ended(outcome)`;
  `combine` = worst outcome, sums). `Ledger::record(pair, run, at)`; `Entry.last_unreadable` is kept with the
  last success, so a later failure does not hide it. (`record` changed signature.)
- `health::assess`/`Health`/`PairHealth`/`Reason`: one rule (SPEC "Health").
- `textfile`: render/parse/`Textfile::{load,save}`/`write_atomic`; fundament's three families under a
  prefix plus `backup_last_unreadable_files` and `backup_last_outcome`; strict read; explicit mode 0644.
- `preserve health [--config F] [--ledger F] [--format text|json] [--now SECS]`, exit 0/1/2, 3 unreadable
  ledger/config, 4 usage. `config.rs`: `/etc/p-reserve.toml` (ledger, metric_prefix, `[freshness]`,
  `[[pair]]`), all optional, unknown keys refused. Catalog: `reprovision` added; `health` marked implemented.
  Usage and "not implemented" exit with 4 (was 2: it clashed with "critical").

Verified (run here, macOS sandbox): `cargo test --workspace --offline`: all pass, 0 failed, 0 ignored,
nothing skipped; `cargo clippy -p p-reserve-core -p p-reserve --all-targets --offline` clean (clippy on the
whole workspace shows warnings in p-act and p-age, not touched); `cargo fmt` applied to my two crates.
New tests: core 34 (outcome order, `incomplete` rule, health rule, textfile round trip with quotes, backslash,
newline and comma in labels, ms precision, fundament-only file, 13 malformed cases with line numbers,
corrupt file is an error not empty, no leftover temp file, mode 0644 under umask 000/002/022/077/277, an
existing 0666 file comes out 0644); `preserve` 5 unit + 7 process tests (exit codes 0/1/2/3/4, JSON
`schema_version`, catalog).
Not verified: behaviour of the file on Linux; a ledger written by real fundament (only a hand-made sample
in its format); Prometheus node_exporter reading it.

SPEC changes (same commit as the code): Status; Core list (Run, Textfile, health); new "Health" section;
verbs line (forget not a verb, prune forgets then prunes, reprovision kept, mount/unmount/unlock out);
`incomplete` moved from "disagree" to decided and out of "Open decisions"; one sentence on why no `unlock` and the
restic-prune hazard; Risks: SFTP row with the trial, `set_devid` row; host runs one-shot verbs (decided);
toolkit provisional; order of work item 5 marked done.

For the designer / owner:
- Defaults of the limits are mine and provisional: fresh_within 26h, stale_after 72h, first_run_grace 1h.
- The order among failures in `Outcome::severity` is mine; a failed run alone is a warning (critical comes
  from age only), which follows "only stale asks for attention".
- Config key names (`[[pair]]`, `metric_prefix`, humantime durations) and the default paths
  (`/etc/p-reserve.toml`, `/var/lib/p-reserve/ledger.prom`) are mine.
- `p_act::settings` reads JSON only and checks owner and mode; the workspace convention is TOML config, so
  I did not use it for `/etc/p-reserve.toml` (it is not a security-bearing file yet) nor for the ledger. I
  will use `p_act::exchange::LineBuffer`/`LineReader` for the socket (unit 3) if its limits suit.

## Unit 3: the daemon protocol proposal (done; for the designer, nothing built)
`proposals/socket-protocol.md`. Merged `integration` again first (brings stage2-mac.md).
- Follows both sets of decisions: 0700 directory, peer read or dropped, one JSON object per line with
  `schema_version`, ids, progress events; **jobs outlive connections** (backup, prune, check, verify, reprovision, restore:
  explicit `cancel {job}` only, `jobs` and `attach` for a later connection); browsing, `read` previews and
  subscriptions end with their connection. A per-operation table is in section 4.
- Section 6 answers the ten requirements of section 8.5 of stage2-mac.md one by one: met 1 (with the exclude/prune-marker/schedule
  nouns named, to be specified with their units), 2, 3, 4, 6, 7, 8, 9, 10; 5 is not applicable now (no question in v1).
- Decisions I made that the designer should look at: only the daemon's own uid is served (root and others dropped, because `restore` writes a
  client-named path); framing limits 64 KiB requests, 1 MiB answers, uses `p_act::exchange::LineBuffer::with_limit`
  (not the p-act message types); paged `ls`, pulled `read` (no streaming); `cancelled` is a job result, not an `Outcome`.
  Six open questions are at the end of the proposal.
SPEC changes (same commit): the desktop-app section marks the web-view recommendation superseded for macOS and states the
two conditions for the SwiftUI front end (browser, exclude store, prune marker move behind the protocol first; section 8.5);
Architecture gains the "jobs belong to the daemon" bullet pointing to the proposal. Not changed: Open decisions (it already
says provisionally SwiftUI).
Verified: nothing to run (a document). `cargo test --workspace --offline` and clippy were not rerun after this unit; no code changed.

## Unit 4: local-repository engine and the CLI verbs (done for a local repository)
First thing, as asked: **the dependency closure builds offline.** `rustic_core` 0.14.0 and `rustic_backend` 0.8.0 with default
features (OpenDAL included) compile from the unpacked registry: `cargo build -p p-reserve-core --offline` took 4 min 17 s (dev, on top
of an already warm cache, machine load average about 120 to 150); rest-only features 3 min 20 s. `cargo fetch --offline` fails on
`windows-sys 0.61.2` (a Windows-only crate that no build here needs); `cargo build/test --offline` do not. No crate to fetch.
Both crates keep `rust-version = 1.91`; I did not take them out of the default workspace build (your call; they are in `p-reserve-core`).

What exists:
- `Engine` gained `dump` and `restore` (`RestoreSummary`). `p_reserve_core::rustic::RusticEngine::open(&Location, password)` reads only:
  open, `snapshots`, `list` (direct children), `dump` (counted), `restore` (absolute destination, nothing overwritten or deleted:
  a file to a new path, a directory into a new or empty one). Outcomes named: `no-repository`, `wrong-password`, `failed`.
  `testing::make_repository` (cfg(test) or feature `testing`) is the only code that writes to a repository: a throwaway one in a temp dir.
- `[[target]]` in the configuration (`name`, `repository`, `password_file`, `options`). The password is read from a file that must be a regular
  file, owned by root or the running user, mode without any group/other bit; never an argument or environment variable.
- `preserve snapshots <target>`, `ls <target> <snapshot> [path]`, `restore <target> <snapshot> <path> --to <dest>`; `--format json` with
  `schema_version` and an `error` record carrying the outcome name; exit 0, 3 failed, 4 usage (a table is in the SPEC).
- Earlier answers applied: strict TOML config (checks on the open file, `p_act::settings::check_owner_and_mode` and `p_act::peer::own_uid`, no copy; unknown
  and doubled keys, 1 MiB limit, no value from the file in any error; `config::read_checked` is the one function to point at p-act's TOML reading);
  per-pair limits (`[[pair]]` + `[pair.freshness]`, `assess` takes limits per pair); a pair never succeeded and past its grace is critical whatever
  attempts follow, tested hour by hour; exit-code table for `health` in the SPEC; defaults documented as assuming a daily schedule.
- Ledger content check (your point 5): it writes only source and target names, outcome names, times and counts. No repository address, credential or path
  from a home. Names are now checked at configuration load (letters, digits `. _ - : + /`, at most 128, no `@`, no `://`, no `..`, no leading `/`).
  A name that is a path under `/home/...` without a leading slash (`home/alice/docs`) would pass: a configured name is the user's choice (not detected).

Verified (run): `cargo test --workspace --offline`: all 38 test binaries pass, 0 failed, 0 ignored, nothing skipped. New: core 8 engine tests (fixture:
three files, one of 2 MiB in chunks; round trip byte for byte; latest, id and id prefix; failures are outcomes not panics; restore refuses overwrite,
relative and `..`; wrong password; no repository; repository directory byte-identical before and after reads), 9 config/6 core health/…; CLI 5 process tests
in `tests/repo.rs` plus 9 in `tests/health.rs`. `cargo clippy -p p-reserve-core -p p-reserve --all-targets --offline` clean; `cargo fmt` applied.
Umask 002/077/022 re-run for the health and core tests before the engine was added; the engine tests write only to temp dirs and set no modes.

**Needs the orchestrator:** the debug build is unusably slow for these tests: with unoptimised dependencies, init takes 137 s and opening 140 s for a 3-file
repository (key derivation and index load; mostly CPU of deps), so the engine tests take about 6 minutes. Measured: release, same tiny repository,
loaded machine: init and snapshot 6.3 s, open 4.3 s. With `--config 'profile.dev.package."*".opt-level=2'` the six CLI process tests ran in 6.6 s.
Please add `[profile.dev.package."*"] opt-level = 2` (or at least for `scrypt`/`rustic_core`/`zstd`...) to the workspace `Cargo.toml`.

Not verified: memory of an open repository; a repository written by restic or fundament; SFTP (the engine takes the OpenDAL options but is untested there);
SHA-256 restore test; large repositories; the `Run`-to-ledger recording by a backup (nothing writes yet); that `dump` of a sparse or very large file streams.
Decisions of mine: `list` returns direct children only (a recursive listing is the caller's); a snapshot spec with `:` is refused (path is a separate argument);
no `dump` verb (the engine has it, the verb list is unchanged). Open for the designer: exit code per outcome (now all failures are 3 with the outcome named).

## Unit 3b: the designer's six answers folded in; the start marker (done)
- `proposals/socket-protocol.md` follows answers 1 to 6 and the additions (section 7 now lists them; the root-helper sentence, the bounded
  `detail`, `cancel_late`, the schedule rule). SPEC: Architecture bullet on jobs, a "run that began and never ended" line, Core list (`marker`, attempt, cause).
- `p_reserve_core::marker`: `MarkerDir::begin(&Job)` writes a 0600 file in a 0700 directory and holds a lock on it for the life of the job;
  `Marker::complete(store, ledger)` saves the ledger then removes the marker; `end()` removes it for a job that wrote no entry (cancelled);
  `MarkerDir::recover(ledger, store)` turns every unheld marker into `failed` + cause `interrupted` per pair (keeps the last success; first attempt set
  from the marker's start), saves, then removes. Skips markers whose lock is held (a live job in another process); skips a pair whose ledger already
  has an attempt at or after the start (crash between save and remove); idempotent; discards empty or damaged markers without an entry.
- Ledger: `Entry.last_attempt` and `last_cause`, `Run::interrupted()`, `Cause`. Textfile: `backup_last_attempt_timestamp_seconds` and a `cause` label on
  `backup_last_outcome`. `health`: reason `Interrupted` (a warning).
- Tests (all run, none skipped): marker 9 (complete order, left-behind marker, idempotence, crash between save and remove, live marker, junk, bad id/second
  marker/unsafe dir, modes 0600/0700 under umask 000/002/022/077, a ledger that cannot be saved keeps the marker); textfile round trip with the cause and two new
  malformed cases. `cargo test --workspace --offline` all pass (54 result lines, 0 failed, 0 ignored), clippy on the two crates clean.
- `detail`: bounded to 512 bytes, control and bidirectional characters replaced (`text::for_display`). **p-act's `text::check` is `pub(crate)`**, so I stated its
  character set a second time; please have p-act export it and I will replace mine.
- The marker is not wired to a `backup` yet: no backup exists (it was not built in unit 4, which stayed read-only). It is the primitive the backup, prune and
  check jobs call; wiring and the one-shot CLI's use are tests-with-the-job later.
- Merged `integration` again; `Cargo.lock` conflicted and was taken from `integration`, then my dependencies were re-added by the build.

## Item 4: SHA-256 restore test, a repository written by restic, switch to p-ermit (done)
- **p-ermit switch**: `p_reserve_core::text::for_display` now asks `p_ermit::text::check` per character (my copy of the character set is gone). Behaviour: same set; mine still *replaces*
  a refused character with a space (a `detail` for a log must still be written), p-ermit's `check` only refuses, so no difference in what is refused. I also moved the
  configuration file and the password file onto `p_ermit::settings` (`read_toml_optional` with the `toml` feature, `read_secret_checked`): my `read_checked`, `read_secret` checks
  and TOML error scrubbing are deleted; `p-act` is no longer a dependency of p-reserve. Error text differs only in wording (p-ermit's). 
- **Engine tests** in `crates/p-reserve-core/tests/engine.rs` (feature `testing`, so out of the default run). All 5 pass, none skipped (`restic` 0.19.0 is on this machine, local repository in a
  temp dir, no network):
  - restore of a whole tree and of every file one by one, SHA-256 of each restored file against the source file (small, empty, symlink as its target, nested, a 3 MiB file of
    several chunks, a compressible one), from a repository written by rustic AND from one written by `restic` 0.19.0 (repository v2, compression on);
  - the engine lists (kinds included), dumps and restores what restic wrote; opening and reading takes no lock and changes no file (`locks/`, `snapshots/`, `index/`, `keys/`
    listings identical);
  - **a restic that is writing** (`restic backup --stdin` holds its lock until its input closes): the repository opens and reads normally while the lock is held; rustic neither
    waits nor refuses and takes no lock of its own (lock count stays 1, then 0 when restic finishes). A snapshot restic wrote after the open is **listed at once** (the list is read
    from the repository each time) but **its data is not in the loaded index**: reading it fails with outcome `failed`, detail "Tree ID ... not found in index", never wrong bytes;
    a new open reads it. So the daemon has to reopen, when that failure comes or when it learns of a new snapshot.
  - Not tested: a repository **exclusively** locked by restic (prune, forget, rewrite hold one briefly; nothing here could hold one open). rustic takes no locks, so it would not notice it:
    reading while restic prunes is the unsafe case the SPEC already names.
- **A flaky test found and fixed**: `textfile::tests` set a umask of `0277` (no owner write) process-wide; a test creating a file at the same moment failed with "permission denied"
  (it hit the engine fixture once). The mask list no longer has `0277` (`0007` instead) and `umask.rs` says why.
- **Commands and times, here (a macOS machine, load average lower than before):**
  default, as the orchestrator's sweep: `cargo test --workspace --offline` 2 min 34 s, all pass, no rustic compiled (62 result lines, one `ignored` is in another crate's doctests);
  the engine tests: `cargo test -p p-reserve-core -p p-reserve --features p-reserve/engine-rustic --offline` 5 min 51 s in all (builds already warm; of which the new
  `--test engine` file 76 s and the lib's engine tests 107 s, the CLI process tests 140 s, run in parallel with each other), all pass. Faster with
  `--config 'profile.dev.package."*".opt-level=2'` (once built), much slower on a cold build.
- Three-umask sweep of my two crates (022, 002, 077) before the engine tests: same counts, 0 failed.

## Audit: strings from elsewhere in preserve's output (read from the code at d9b7ee2, nothing changed, nothing run)
"Passed the rule" means the character rule (`p_ermit::text`) was applied before the point. `for_display` (mine) *replaces* refused characters with a space and cuts to a
length; it is not the escape form. serde_json escapes only U+0000 to U+001F, so C1 (U+0085, U+009B) and bidirectional marks pass through JSON raw.

| # | Site | Where the string comes from | Passed the rule? | What a control char, ESC or U+202E does there |
|---|---|---|---|---|
| 1 | `snapshots` text: host, paths | the snapshot file; written by whoever wrote the repository (restic, another machine) | **No** | on the operator's terminal: ESC rewrites the screen or the title, a newline fakes a line, U+202E reorders the text |
| 2 | `snapshots` JSON: `host`, `paths`, `tags` (ids are hex) | same | **No** | a front end's list shows it as is; C1 and bidi marks survive JSON |
| 3 | `ls` text: file name | the snapshot's tree: the bytes the source file system held. Taken as `node.name().to_string_lossy()` | **No**; also **lossy**: invalid UTF-8 becomes U+FFFD, not reversible | terminal as in 1; a file named with a newline looks like two entries |
| 4 | `ls` JSON: `name` (lossy as in 3); echoes the `snapshot` and `path` arguments | tree; the arguments are the operator's own (later a front end's) | **No** (name); arguments not applicable to the CLI, **yes to the socket** | as 2 |
| 5 | `restore` text/JSON: destination (argument echoed), counts | the operator's argument; numbers | n/a (own input) | none from the repository |
| 6 | `restore` on disk | node names from the repository | rustic's `LocalDestination::path` refuses `..`, a root or a prefix component (read, `local_destination.rs:218-240`, not run), so a crafted name cannot leave the destination; names with a newline, ESC or bidi mark are created **as they are** (real name, which is right); a name holding `/` is split into nested directories | on disk: the real name, a file that the next `ls` of that directory will show raw |
| 7 | `dump` / `read` (engine returns bytes into a writer; the protocol's `read` is base64) | file contents | n/a: bytes in a field, never spliced into text | none |
| 8 | engine errors: `EngineError.detail` (`fail` and `named` in `rustic.rs`) | rustic's own message: quotes paths, tree ids, context values, repository data | **Yes**, replaced + cut at 512 bytes, in `fail()` | passed; but see 9 |
| 9 | forwarding of 8: stderr text `preserve <verb>: <outcome>: <detail>` and the JSON `error` object's `detail` (`repo.rs`) | 8 | passed the character rule, but the workspace rule says rustic's text goes only to a log, escaped and bounded | JSON `detail` reaches machines and front ends: **should go** (the outcome is the code); stderr is the operator's log: keep, with the escape form |
| 10 | `repo.rs` `plain()` (config, password file, no engine) | p-ermit's error text, which names the path (from the command line or the configuration) | **Yes** (`for_display`) | passed |
| 11 | `health` text: source and target | **declared pairs**: validated by the name class at config load. **Without declared pairs: the ledger file's labels** | declared: yes. **From the ledger: No** | terminal: as 1; the ledger is a file another writer could have touched (root, same user) |
| 12 | `health` JSON: same two strings | same | same | as 2 |
| 13 | `health` errors on stderr (`preserve health: ...`) | p-ermit's and `textfile::Malformed { line, problem }`; `problem` embeds `{:?}` of an unknown label, outcome or cause **from the file** | **No** (not through `for_display`), and it **repeats the offending value** against the new rule (Debug escapes controls; it is not guaranteed for bidi marks) | terminal; must say line and what is wrong, not the value |
| 14 | ledger **writer** `textfile::render`: pair names | `Pair` strings from config (class-validated) but `Ledger::record` takes any string; marker recovery supplies names from a marker file | **No** at the writer; label escaping covers `\\`, `"` and newline only: ESC, `\r`, C1, bidi are written raw into a file that node_exporter and people read | a monitor or a person reading the file |
| 15 | ledger **reader** `textfile::parse` | the ledger file | accepts any characters in a label value; they feed 11 and 12 and are written back by the next save | as 11 |
| 16 | marker file: `Stored.pairs`, `job` read back in `recover` | a file in a 0700 directory of the same user | job id validated at `begin` but **not on reading back**; pair names not validated | flows into 14 and into `Recovered` (printed later) |
| 17 | `check_name` refusal shows the name | the configuration | **Yes** (`for_display`, 64 bytes) | passed (replace, not escape; the designer's exception: the name is shown) |
| 18 | usage and unknown-verb text: `unknown verb '{other}'`, `unknown argument {flag:?}` | the operator's argv | no, but own input | negligible; Debug in some, raw in `main.rs` |
| 19 | job messages and the socket's `detail` | not built | by design: bounded + the rule (proposal, section 2) | to be built with the escape form |
| 20 | catalog, usage, `health` level words, reasons, outcome and cause names, freshness, times, byte counts | constants, closed enums, numbers | n/a | none |

Count: **20 sites; 13 touch a string from outside** (1, 2, 3, 4, 6, 8, 9, 11, 12, 13, 14, 15, 16). **Not covered: 1, 2, 3, 4 (name), 11 (ledger-derived), 12 (ledger-derived), 13, 14, 15, 16; and 9 for JSON.**
Covered: 5, 7, 8, 10, 17, 20 (and 19 by design, 18 own input, 6 by rustic's path check).

What I would do (nothing done yet):
- **Escape form** (`p_ermit::text::escape`, with its report of whether anything was escaped) at **output** for: `snapshots` host/paths/tags and `ls` names, text and JSON (JSON gets an `escaped: true` marker on the
  record that had any), and `health` pair names from the ledger. For `ls`, take the name as bytes (`OsStr`, not `to_string_lossy`) so a name that is not UTF-8 is shown with `\x{..}` and is reversible; a file named
  with a newline, ESC, C1 or U+202E is listed, as what it is, never refused and never raw.
- **Validation at entry** for the ledger: `Pair` names through the name class when they are made (config) and, on **reading** a ledger or a marker, `p_ermit::text::check` (not the class: a fundament ledger has names like `tank/home`);
  a refusal names the line and not the value. And the **writer** refuses (or escapes) rather than write a control or bidi character into a file.
- **Errors**: `textfile::Malformed.problem` and every message of mine say line and what, never the value; engine `detail` stays out of JSON, goes to stderr only escaped and bounded (the escape form instead of my replace-by-space).
- **restore** must restore the real name on disk and only the output is escaped; rustic does that. The test the workspace rule asks for: a snapshot holding a file named with U+0085, U+009B and U+202E (and ESC and a newline, and one with invalid UTF-8
  if restic can store it), listed in text and JSON, dumped (bytes equal), restored (the on-disk name is the real one, the output shows it escaped), and a ledger or marker with such a name refused or escaped, through every output preserve has.
- `for_display` stays only where a string is bounded for a log; it is not the escape form and goes away when the escape lands.

## The audit's fixes (done), and the three answers asked for again
- Merged `integration`; `p_reserve_core::text` is a thin layer on `p_ermit::text` (`escape`, `escape_bytes`, `escape_clipped`); my `for_display` is deleted. `for_log` (escaped, 512 characters) is for rustic's words and errors; `shown` for an argument echoed in an error.
- **Sites fixed** (numbers of the audit table): 1, 2, 3, 4 (host, paths, tags and names through the escape form, names as **bytes** via `Node.name: Vec<u8>`, records marked `"escaped": true`; arguments echoed
  in `ls` JSON and the restore destination escaped); 9 (no `detail` in the JSON `error`; stderr text escaped and bounded); 11, 12, 15 (the ledger is read with `p_ermit::text::check`); 13 (ledger errors say the line and what, never
  the value; `health` stderr through `for_log`); 14 (`Textfile::save` refuses a name the rule refuses, nothing written); 16 (a marker with a bad name or job id is discarded without an entry); 17 (the refused name shown escaped, 64 characters);
  18 (argv echoes escaped). 6 was already right (rustic restores the real name; read, and now tested).
- **Tests** (all run; engine tests need the feature): a file named with U+0085, U+009B, U+202E, ESC and a newline in a snapshot, from a repository written by rustic and by restic 0.19.0: listed (bytes equal), dumped (bytes equal), restored (the
  on-disk names are exactly those); through the CLI: `ls` text (no raw refused character on stdout, one line per name, the escape form present), `ls` JSON (each entry `"escaped": true`, reversible with `unescape`, an ordinary name `false`),
  `restore` (real names on disk, output clean), an error about a weird missing path (stderr and JSON clean, no `detail` in JSON). Default-run tests: ledger with a bad name refused on read and write with the line only, errors without the value,
  markers with bad names or ids discarded, `health` on such a ledger exits 3 and prints nothing raw.
- Default sweep and 3-umask sweep of my crates pass; the engine suite: `cargo test -p p-reserve-core -p p-reserve --features p-reserve/engine-rustic --offline`: all pass, none skipped, 10 min 45 s here on a loaded machine
  (the `--test engine` file alone: 7 tests, the lib's engine tests 56 in 71 s, the CLI process tests 245 s in parallel).
- What 6bfc376 and the commits after 2235bc2 contain: 6bfc376 and the commits after 2235bc2 up to here are: p-ermit for the character rule, settings and password file (and `p-act` dropped); `tests/engine.rs` (SHA-256 restore, a restic-written repository, a writing restic: item 4);
  a fix of a flaky umask test; the audit (c0d9aa0); and this unit.
- Still open: the proposal's job messages and socket are not built; `Outcome`-per-exit-code; the SHA test is against local repositories only.

## Second round of the audit's fixes (done)
Built as assigned; changes against the first round:
- **The ledger and the marker are read and written by the name class** `[a-z0-9][a-z0-9._-]{0,63}` (designer's decision; `is_name`/`NAME_RULE` now live in `p_reserve_core::ledger`, config uses them): a name outside it, a control character or bidi
  mark included, refuses the **whole file** on reading (the line, never the value); `Textfile::save` refuses before writing anything (the file is left untouched); a marker with such a name or a bad job id is discarded without an entry. A fundament
  ledger with `tank/home` is refused whole (tested); no import is built.
- **Escape form with bounds**: `snapshots` and `ls`, text and JSON, escape every string from the repository (`escape_clipped`, names through `escape_bytes_clipped`: **bytes all the way**, `Node.name: Vec<u8>`; no `to_string_lossy` is left in the path),
  `"escaped": true` and `"clipped": true` on a record. **Proposed bounds** (characters of the escaped form, an escaped byte is up to six): name 1024, path 8192, host 512, tag 512, an echoed argument 128 (snapshot) or 8192 (path). Text output marks a cut with `…`.
- **Engine errors**: the text is the escape form (never a space), cut at 512 characters, goes to stderr only; the JSON `error` is the outcome (a closed code) and nothing else.
- **Tests**: weird names (U+0085, U+009B, U+202E, ESC, newline) from rustic- and restic-written repositories, through engine and CLI, as before; **names that are not UTF-8** (two that differ only in byte order): listed as bytes, shown `bad\x{ff}\x{fe}name` and `bad\x{fe}\x{ff}name`, reversible, restored with the real bytes: **SKIPPED on this machine** (APFS refuses
  such names, 3 tests say SKIPPED and count as not run); they have to be run on Linux. Strict mode: `PRESERVE_TESTS_STRICT=1` turns each SKIPPED into a failure (the README's rule; the restic tests too).
  Limitation seen: `dump` and `restore` take a `&str` path, so a file whose name is not UTF-8 is reached by restoring its directory; listing and restoring are tested that way.
- Verified here: 3-umask sweep of my crates; engine suite `cargo test -p p-reserve-core -p p-reserve --features p-reserve/engine-rustic --offline` passes (21 min 11 s on a machine with a very high load; was 10 min 45 s before), 3 SKIPPED.
- Not yet applied from the README's test paragraph: explicit modes for the files the tests create (`fs::write` in the engine and CLI test fixtures takes the umask); the ledger files in `tests/health.rs` too. They do not depend on the mode today.

## What else reads or writes the ledger file (the question)
In this workspace **only preserve**: `p_reserve_core::textfile::Textfile` (read by `preserve health`; written, once built, by the backup/prune jobs and by marker recovery). Nothing else in `crates/` or `doc/` refers to it. Outside it: the node exporter's textfile
collector reads it (that is what the format and the 0644 mode are for), and people with `cat`. **It is not shared with fundament's tooling:** fundament's Python host kit writes its own ledger (`fundament_backup_*` under its own prefix, names such as `tank/home`) with its own code; preserve would need to read
it only once, at a switch of writer, which is the import the designer left unbuilt. So the file is preserve's own.

## The case not tested: a repository restic holds under an exclusive lock (commands for the owner's machine)
`restic prune`, `forget --prune` and `rebuild-index` take an exclusive lock; rustic takes no lock and so would not notice it. To see what the engine does, hold such a lock without racing:
```
R=/tmp/excl-repo; export RESTIC_PASSWORD=pw
restic -r $R init
dd if=/dev/urandom of=/tmp/excl-src.bin bs=1m count=256        # Linux: bs=1M
restic -r $R backup /tmp/excl-src.bin; restic -r $R backup /tmp/excl-src.bin
restic -r $R forget --keep-last 1 --prune &                    # takes the exclusive lock
P=$!; until [ -n "$(ls $R/locks)" ]; do sleep 0.1; done; kill -STOP $P
restic -r $R cat lock $(restic -r $R list locks | head -1)     # expect "exclusive": true
# with a [[target]] named excl in a configuration (repository = "/tmp/excl-repo", password_file with 'pw', mode 0600):
preserve snapshots excl; preserve ls excl latest /tmp; preserve restore excl latest /tmp/excl-src.bin --to /tmp/excl-out.bin
kill -CONT $P; wait $P
```
Expected from the rustic code (read, not run): all three work as if there were no lock; reading during the repack's delete step is the unsafe case the SPEC names (a pack the index lists may already be gone: `failed`, never wrong bytes, but this is not run).
