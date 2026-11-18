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
