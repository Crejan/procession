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
