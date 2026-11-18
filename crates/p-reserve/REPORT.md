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
