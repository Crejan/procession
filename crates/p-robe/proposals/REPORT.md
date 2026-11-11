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

---

## Update: `probe serve` for stage 1, everything but the HTTP transport

Merged `agent/p-act` (7d8e371 and what came before it) and `integration`.

### The blocker, first: no HTTP server can be built here

Asked for before building: which crates for HTTP, and are they in the local
registry? The registry's **cache** has `hyper` 1.11, `hyper-util`, `http-body-util`,
`axum` 0.8, `tokio`, `tokio-rustls`, `rustls`, `httparse`, `http`, `reqwest`;
**no** `tiny_http` or other small server. But a build needs the crates
**unpacked** in `~/.cargo/registry/src`, which this sandbox does not let cargo
write to. A scratch project with `hyper`, `hyper-util`, `http-body-util` and
`tokio` (`cargo generate-lockfile --offline`, then `cargo build --offline`)
fails at the first crate: `failed to unpack package atomic-waker v1.1.2 ...
failed to create directory .../registry/src/.../atomic-waker-1.1.2: Operation
not permitted`. Only what is already unpacked builds: `tokio` 1.54.1, `http`,
`httparse`, `bytes`, `serde_json`, `base64`, `ring`, `libc`, `tempfile`. There is
no server among them; `httparse` is a parser. I did **not** write an HTTP/1.1
server by hand, as asked. **Decision needed from you:** unpack `hyper` and its
dependencies where cargo can read them (or lift that restriction), or accept a
hand-written server over `httparse` and `tokio` for stage 1 (I advise against
it), or take the HTTP layer from another place.

Because of this, **`probe serve` does not listen**: it builds the service from
its settings, checks pledge's socket, and exits 2 with "the HTTP transport ... is
not built yet". The MCP layer is a function (`mcp::Mcp::handle`: HTTP request in,
HTTP response out), tested in-process; a transport only has to read a request
off a socket, call it, and write the response (a cancel flag it sets when the
connection drops). What is not built because of it: the socket, TLS (stage 2),
and **SSE streaming** (progress notifications and the 15-second keepalive that
`review-pact.md` asks for, which `pact`'s idle timeout depends on): the layer
answers once. Nothing in this unit ran over real TCP.

### What exists (all in `crates/p-robe`)

| File | What |
|---|---|
| `service.rs` | the steps of the SPEC for one call: checks, rate (`Mode::Name`), request signed with the service's key, identifier recorded, submit, wait, verify the approval, run, with a log line (exact code) for each |
| `pledge.rs` | the client of `service.sock`: door checks from this side (directory and socket not symlinks, the person's uid, the peer's uid), one request per connection, `ClearancePolicy::Refused`, `cancel` when the agent goes, own deadline timer, an unknown `result` is no answer |
| `store.rs` | used identifiers on disk (`<dir>/<uuid>`, created exclusively, fsynced with the directory), forgotten after their deadline |
| `outcome.rs` | the coarse list for an agent and the mapping from pledge's and the broker's exact codes, one test per code |
| `mcp.rs` | JSON-RPC/MCP: `initialize`, `ping`, `tools/list` (from the table), `tools/call` with `_meta` `procession/call` and `procession/call_sig`; header and size rules; busy is 503 |
| `runner.rs` | `sudo -n -- probe --within <signed rating> <noun> <verb> ...`; `InProcess` for tests |
| `config.rs`, `serve.rs`, `setup.rs` | `/etc/probe.toml`; `probe serve`; `probe setup --host-key <file>`: the service's key and a 30-day certificate for `probe@<host>` made with `ssh-keygen`, saying plainly that a site's roll-out does this later |

Choices of mine inside the rules: the service takes approvals from one
configured person; a call whose certificate names another person is
`approval-invalid` with `person-mismatch` (p-act's `PersonKeys` attaches the
configured keys to whatever person the call names, so this check is the
service's own, and it is the one that stops an approval by the right key for
the wrong person); every run goes through one mutex because the dispatcher's
lock is per identity and all calls of the service have the service's; the
dispatcher's exit codes 64, 3, 75 become `refused/not-allowed`,
`unavailable`, `refused/try-later` (a verb that itself exits 64, 3 or 75 is
indistinguishable from the dispatcher refusing; stated, not solved).

### Verified

`cargo test -p p-robe`: 108 unit + 3 CLI; with `--features test-verbs`: 113 unit +
18 CLI. Clippy clean in both. fmt applied. The service is tested against a fake
pledge in the test that speaks the codec over a Unix socket (bound under
`/tmp/claude/`) and signs with `sign_approval` using throwaway `ssh-keygen`
keys, and against calls composed and signed in the test (a delegation key
certifying an agent key); the fake verifies each request under the host key, so
the service's signing is checked by a real `ssh-keygen -Y verify`. Covered:
approved with the confirmed key; the automatic key accepted below the top and
refused at the top of one scale (`test peak`), the confirmed key running it;
declined; refused (`ceiling`, `muted`, `malformed`, `service-mismatch`); expired by
pledge and by our own clock at the deadline; an approval arriving after the
deadline runs nothing; an approval over other bytes; by another key; by the
right key for another person; a call for another host, another service, an
unknown or unavailable verb, parameters not accepted, a deadline past or too far;
the tool call differing from the call; a used identifier (also while the first
call waits); a restart with identifiers on disk; a cancel when the agent goes
(and a later approval running nothing); an unknown `result` as no answer; a
broken connection not retried; clearance members refused in stage 1; the door
(wrong uid, symlink, no socket); a store that cannot be written; the bound on
waiting calls; `--within`: a link planted between the service's rating and the
dispatcher's opening reaches the agent as `refused/not-allowed` and the verb
does not run; the MCP layer with `_meta` (list, call, spent call, missing and
extra keys, an unknown tool, `Origin`, protocol version, `Accept`, `Content-Type`,
size); `probe setup`.

### Not verified

- **The sudo path** (`SudoRunner`): only its argument vector is tested. No test
  runs as root, and no sudoers rule was written or tried. The tests run the
  dispatcher in the test process as a caller that is root (`InProcess`).
- **Real TCP and any HTTP**: nothing; see above. No SSE.
- **Linux**: the peer check (`SO_PEERCRED`) is written for Linux and never run
  (macOS `getpeereid` ran), as is `/proc/self/fd`.
- The branch of `decide` that refuses an approval that arrives *just* before the
  deadline but is verified after it (`approval-after-deadline`) is not hit by a
  test: the wait itself ends at the deadline.
- `probe setup` was run with a throwaway host key as the current user, not as
  root on a host with `/etc/ssh/ssh_host_ed25519_key`.

### Needs

The HTTP decision above. From p-act: nothing new. From pledge's side: the
fake in `service_tests.rs` is what stands in for it until pledge's development
form exists; it speaks exactly `p_act::exchange`.

---

## Update: the stream `pact` needs (`pact.md` section 7, commit 32ea5dc)

**Confirmed, and built into the MCP layer** (`mcp.rs`, `service.rs`): when a call
carries a `progressToken`, the response head (`text/event-stream`) is written as
soon as the service has **accepted** the call (first checks passed, a place to
wait reserved), not at the first notification; then a `: keepalive` comment at
least every 15 seconds while the person is asked and while the verb runs;
two fixed-text progress notifications; the JSON-RPC response as the last event.
Refused before acceptance (`invalid`, protocol error, `503`) is plain JSON.
Without a token: plain JSON when decided. A failed write, or the transport's
cancel flag, cancels the call. The final message is at most 4 MiB (asserted at
compile time against the dispatcher's 1 MiB cap); notifications and comments
stay far below `pact`'s 64 KiB. The MCP layer now writes through a
`ResponseWriter` (`head`, `body`, each written at once), which is all a transport
has to implement; `Mcp::handle` collects a response whole for tests.

Also: a verb is killed after 10 minutes (`RUN_LIMIT`, `unavailable`); a limit per
verb in the table is not built.

**Tested** (in-process with a recording writer and a fake pledge): the head at
acceptance, long before an approval that takes 1.2 s; at least 5 comments while
waiting, none of the gaps in the stream above 0.5 s with a 100 ms keepalive; the
two notifications in order with the token and increasing `progress`; comments
while a verb runs (the dispatcher held up 0.9 s); plain JSON for a call refused
before acceptance and for `503`, and without a token; a client that is gone
cancels the call and nothing runs. `cargo test -p p-robe`: 114 unit + 3 CLI;
with `--features test-verbs`: 119 unit + 18 CLI; clippy clean.

**Does not fit, to say rather than choose silently:** nothing in how the service
is served. One point: the 15-second keepalive and the head-at-acceptance need a
transport that **writes and flushes each piece at once** and notices a closed
connection on write (or sets the cancel flag); `hyper` can (a streaming body
with a channel), a hand-written server could. That is a requirement on the
transport, which still is not built (see the blocker above).

---

## Update: the two progress notifications are gone

Removed on the designer's decision: the service sends no `notifications/progress`
(no "handed to your person's machine", no "approved, running"). Kept: the head at
acceptance, the `: keepalive` comments, the final response. `Event` has one
member now (`Accepted`). `agent-to-service.md` section 7 says so; the streaming
test now asserts that the only message in the stream is the answer. Tests:
114 unit + 3 CLI, and with `--features test-verbs` 119 unit + 18 CLI; clippy clean.
Waiting for p-act's `PersonKeys` with the person: then I switch to it and keep my
own `person-mismatch` test.
