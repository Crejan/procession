# p-robe report: step 1 (dispatcher) and the two proposals

The dispatcher is built and committed on `agent/p-robe`. `probe serve` is not started. The only unverified part is Linux behaviour. There are two proposal documents.

## What changed

Commits:
- `1f7d33f`: the dispatcher, the verb table with `sys kit`, and the test verbs behind a feature.
- `aeeedda`: the two proposals.
- `cbef933`: renames the `kind` parameter in `json.rs` to a design term (`record_type`).

Only `crates/p-robe` changed, plus `Cargo.lock`. The new dependency is `libc`, which was already in the lock file. `rating` is still imported from p-ledge.

`probe` now has these entry points:
- `sudo -n probe <noun> <verb> [args]` runs one verb.
- `probe <noun>`, `probe catalog [--format json]`, `--help` and `--version` need no sudo and no audit line.
- `probe serve` still answers "not implemented" and exits 2.

The table:
- `sys kit` is implemented. It reports the installation, every verb with its status, and a summary with `usable`, `problems` and `warnings`.
- `rt irq`, `rt procs` and `rt jitter` are declared as `unavailable` ("needs prover, which is specified and not built"). Calling one exits 3.
- `run command` is `service-only`. The dispatcher refuses it with or without arguments.
- With `--features test-verbs` there are two do-nothing verbs: `test echo` (harmless) and `test peak`. `peak` is rated `open/none/outage`: the top of one scale only, so one top rating alone must demand the confirmed key. `sys kit` warns when it runs in a test build.

Exit codes: 0 ok, 3 unavailable (or no audit line could be written), 64 refused, 75 busy, and a verb's own code otherwise.

## What was verified, and how

Commands, all with `--offline`:
- `cargo test`: 53 unit tests and 2 CLI tests pass.
- `cargo test --features test-verbs`: 53 unit tests and 10 CLI tests pass.
- `cargo clippy --all-targets` is clean, with and without the feature. `-W clippy::pedantic` still gives about 15 style warnings in p-robe that I did not fix.
- `cargo fmt` is applied.
- I ran the real binary on macOS as a non-root user: the refusal exits 64 and went through the real `logger`.

Which `diag-tools` rules are covered by which tests:

| Rule | Tests |
|---|---|
| Tokens match `[a-z][a-z0-9-]*` | `rules::tokens`, `dispatch::a_call_names_a_noun_and_a_verb_of_the_table_and_nothing_else_runs` |
| Argument class, and no leading `-` | `rules::arguments_…`, `rules::no_argument_starts_with_a_dash`, `dispatch::an_argument_is_checked_against_the_class_the_length_and_the_dash_rule` |
| At most 64 arguments of 512 bytes | `rules::an_argument_is_at_most_512_bytes`, `dispatch::at_most_64_arguments` |
| Arguments must be UTF-8 | `dispatch::an_argument_that_is_not_utf8_is_refused` |
| Identity comes from `SUDO_USER` and root | `dispatch::only_a_login_that_came_through_sudo_as_root_is_let_in`, CLI `the_caller_does_not_choose_the_identity_by_arguments` |
| One JSON object per line, header first | `json::*`, `dispatch::sys_kit_answers_one_json_object_per_line_a_header_first`, CLI test-verb test |
| Every answer is capped | `answer::at_the_cap_…`, `dispatch::every_answer_is_capped` |
| An audit line before and after each call | `dispatch::a_line_before_and_a_line_after_each_call_with_who_and_what`, CLI echo test |
| No first line, no run | `dispatch::a_call_whose_first_line_cannot_be_written_does_not_run`, `the_start_line_comes_before_the_answer`, CLI `no_audit_no_run` |
| Caller bytes cannot add an audit field or line | `audit::*`, `dispatch::what_a_caller_calls_himself_cannot_change_the_audit_line`, `the_refusal_line_holds_what_was_asked_…` |
| One call per identity at a time (flock, no symlinked lock, "nolock" event) | `lock::*`, `dispatch::one_call_per_identity_at_a_time`, `a_symlinked_lock_file_is_a_refusal`, `without_a_lock_directory_…`, CLI busy test |
| Exit codes 3, 64, 75 | the dispatch tests above and the CLI tests |
| The dispatcher refuses `run command` | `dispatch::the_fallback_command_is_refused_with_or_without_arguments`, `table::the_fallback_command_is_rated_…` |

Deliberate differences from `diag-tools`:
- `nouns.d`, the `agent` key identity, `catalog note=` and the forced-command entrance are dropped. The key entrance and the window are gone with the design.
- Two-word nouns are not ported; the table has none.
- Arguments arrive as argv and are not re-split on spaces. An argument containing a space is refused, which is stricter than before.
- Identities are limited to 32 characters because the name becomes a lock file name.
- The audit line is written by `logger` run from `/usr/bin` or `/bin` with an empty environment, not from `PATH`.

## What is not verified

- **Linux:** none of it has run on Linux. The audit command line is unit-tested, and the real `logger` call ran on macOS only. That `logger -p auth.info` lands in the expected syslog file is untested. The default lock directory `/var/lib/probe/locks` is my choice. The root-owned and mode checks on it are tested only as a pure function.
- **Root:** the entrance requires `euid == 0` and `SUDO_USER`. No test runs as root. The CLI tests use the test feature's `PROBE_TEST_SANDBOX` override, which moves the audit and locks into a directory and waives the root check. That override exists only in builds with `test-verbs`. A production build ignores it, and a CLI test checks this for the non-root case.
- **sudo:** a real `sudo -n probe` run, the sudoers rule and the environment sudo keeps are untested.
- **Lock inheritance:** lock inheritance by a child verb is not implemented because no verb is a child process yet.

## The two proposals

- `crates/p-robe/proposals/agent-to-service.md`
- `crates/p-robe/proposals/rating-rule.md`

`agent-to-service.md`:
- **Signer:** an agent-side piece signs the call, not the model.
- **Endpoint:** one stateless `POST /mcp`, with no MCP session id.
- **Headers:** `Procession-Call` carries the call as base64. `Procession-Call-Signature` carries the armoured signature, base64-encoded again, so the signed bytes are never re-created.
- **Tool names:** the tool name is the action with `_` for the space. The body must equal the signed call; the service acts only on the signed call.
- **Tool list:** derived from the verb table. Only `ready` rows are listed.
- **What an agent sees:** a first-line outcome object for `done`, `declined`, `refused`, `expired` and `unavailable`. The `refused` reasons are a fixed coarse list.
- **Cancelled calls:** a cancelled or dropped call is never run.

`rating-rule.md`:
- **Row format:** `floor` plus typed parameters. The types are `path`, `choice`, `number` and `plain`.
- **Rating:** the worst of the floor and every parameter's contribution, as data in `table.rs`. One generic function, `rate`, reads it. Tests assert that the declared worst case equals the derived one.
- **Paths:** open once, `fstat`, take the resolved path from the open descriptor, cross-check device and inode, match by whole components with the longest prefix winning, then read that same descriptor.
- **Problem I could not settle alone:** the service (unprivileged) rates and the dispatcher (root, via sudo) reads. sudo closes descriptors above 2, so the same open file cannot be passed along. I propose `sudo -n probe --within <e>,<d>,<dis> <noun> <verb>`: the dispatcher re-rates itself and refuses if its rating is higher than the approved one. The flag can only restrict.

## What I need

- **p-act:**
  - Parsing of a call from the two header values, keeping its bytes and signature untouched.
  - `rating` to move there; tell me when to switch the import.
- **p-ledge or the connections documents:**
  - A reason code from the section 6 list in "no" answers.
  - A way to tell pledge that a call was cancelled.
  - An owner for the agent-side signer.
- **Orchestrator:** the workspace `Cargo.toml` needs nothing. `SPEC.md` still says "five verbs, nothing runs"; it needs updating (I did not touch it) once this state is accepted.

## Open questions for the designer

1. **`--within` flag and the sudo rule.** Are they acceptable? The service's account needs `probe --within *` in sudoers, which is wider than a person's rule. The alternative is a root service, which I advise against.
2. **Header size.** Calls in headers can reach about 28 KiB, and many servers cap headers at 8 KiB. Either keep calls under about 6 KiB and raise the limit to 32 KiB, or move the call into the body, which changes the decision.
3. **Confidentiality.** Answers can be `secret`. Stage 1 is loopback or a socket on one machine. Across hosts the connection needs TLS, and nothing says whose certificate.
4. **`wait_seconds`.** The model may choose how long the person waits, up to 10 minutes. Is that intended, or should only the signer decide?
5. **How much of the reason a `refused` agent learns.** I propose a coarse fixed list.
6. **`/tmp` and other world-writable places** in path prefix lists, where links can be planted.
7. **Declined without a reason.** The approval format has no field for a person's note. Is `person-declined` all the agent should learn?

---

## Update: `rating` from `p-act`, and the reconciliation

- Merged `agent/p-act` (7af0acd). `Cargo.lock` conflicted; I took p-act's side
  and let `cargo` re-add nothing of mine (p-robe's own dependencies are
  `p-act` and `libc`). `p-robe` now depends on `p-act` by path and no longer on
  `p-ledge`; `rating` is imported as `p_act::rating`.
- Verified: `cargo test -p p-robe` 53 unit + 2 CLI pass; with `--features
  test-verbs` 53 unit + 10 CLI pass; `cargo clippy --all-targets` has no
  warning with or without the feature; `cargo fmt` applied.
- Not changed: `SPEC.md` still names p-ledge as the owner of the shared
  vocabulary (lines about "The vocabulary shared with p-ledge"); the
  orchestrator owns that text.
- Taken on board for step 2, no code yet: `submit`/`answer`/`cancel`, the
  request's hash as correlation (no `ref`), `refused` and `expired` carry `by`,
  closed reason lists with `unknown`, stage 1 refuses clearance members and a
  stage-2 service requires them by configuration, **one request per connection
  for both stages**. In `agent-to-service.md` I changed only the paragraph on
  how many calls wait (it was tied to 16 open asks on one connection): now a
  setting, default 16, bounding open connections. The reason list there still
  uses the names of the p-ledge proposal; it needs a re-read against the final
  connections document (`by` in particular: an agent should learn who said no
  only as far as the designer allows).

---

## Update: the rating rule and `--within` (designer's decisions at f4a97a7)

Merged `integration` (f4a97a7).

**Implemented** (`src/rate.rs`, `src/table.rs`, `src/dispatch.rs`, `src/testverbs.rs`):
- A row's `args` is `None`, `Some` (rated at the row's worst) or
  `Params { floor, params }`. A parameter is a `Path` (prefix list, longest
  whole-component match, `otherwise`), `Choice`, `Number` (with steps) or
  `Plain`, found by position or `key=`. One generic function `rate(verb, args,
  Mode)`; `Mode::Open` (the dispatcher: open once, `fstat`, name from the
  descriptor, device/inode cross-check, file kept and given to the verb) and
  `Mode::Name` (the service: `canonicalize` and `stat`). A test asserts every
  row's declared worst equals the one derived from its floor and parameters.
- The world-writable rule: no rating below the row's worst under a directory with a
  group or other write bit (or one that cannot be looked at), for the
  directories from the entry's to the file's parent, and the file itself if it
  is a directory.
- `sudo -n probe --within e,d,dis <noun> <verb> ...`: read before the noun
  only; the dispatcher rates again at the open and refuses (64, `refused` line
  `above-approved`, nothing runs, no start line) if above. It only restricts.
- `test read <path>` (test builds): rated by `<sandbox>/open/`; reads the open
  descriptor. The catalogue prints `param` records with the rules.

**Verified:** `cargo test -p p-robe`: 73 unit + 2 CLI; with `--features
test-verbs`: 73 unit + 17 CLI. Clippy clean in both. fmt applied. Tests cover:
prefixes by whole components, longest entry raising and lowering, links out of
and into an open place, `..`, loose directories (0777, 0775, 0757, 1777; the
entry directory itself; an exact entry's parent), unreadable and missing files,
FIFO and `/dev/null` refused, relative path, a link replaced between the
service's rating (`Mode::Name`) and the dispatcher's (`Mode::Open`) at function
level and end to end (`--within open,none,none` refused, no start line), a
malformed `--within`, `--within` as an argument.

**Not verified:** Linux. `readlink /proc/self/fd/<n>` is written and never run
(tests ran on macOS with `fcntl(F_GETPATH)`); the deleted-file name on Linux and
the permission behaviour as root are reasoned, not run. Access lists and mount
options are not looked at by the writable-directory rule. No sudo run.

**MCP `_meta`** (checked on 2026-11-11 against the 2025-06-18 specification, fetched
from modelcontextprotocol.io): `_meta` is reserved for additional metadata with
free keys of the form `prefix/name` (reserved only for prefixes naming `mcp`
or `modelcontextprotocol`); `procession/call` and `procession/call-signature`
are valid. The base request type carries `params._meta`; the schema's
`CallToolRequest.params` is written `{name, arguments?}` without it, which is
the one thing to know (SDKs accept it; our server and `pact` are our own). I
did not fall back to headers. Documented in `agent-to-service.md`, section 3.

**Documents updated to the decisions:** `agent-to-service.md` (rewritten: `_meta`,
the coarse list and its mapping, the signer as `pact`, deadline, no "shown",
TLS open, identifier recorded at submit, one request per connection) and
`rating-rule.md` (decided/implemented, the world-writable rule, `--within`,
Linux not run).

**Needs:** `pact`'s interface to review; the exchange codec (`submit`, `answer`,
`cancel`, `Reason`) in `p-act` before `probe serve`. SPEC.md still lists the
"first table" as in `src/main.rs`; the orchestrator owns it.
