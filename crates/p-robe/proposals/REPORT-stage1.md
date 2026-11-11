# Stage 1, first cross run: pledge, pact and probe

> **This is not stage 1 done.** `doc/approvals.md` section 8 defines stage 1 as
> one **Linux** machine, with a real sudo rule between the service and the
> dispatcher. Everything below ran on macOS, in one process for the service and
> the dispatcher, with no sudo and no HTTP. Three passes of this test (and
> more since) show that pledge, `pact` and the service fit each other in
> their messages, their records and their timing; they do not show that the
> sudo rule, the service's account, the sockets' permissions, `SO_PEERCRED`,
> `/proc/self/fd` or the HTTP transport work. Stage 1 is done when this same
> test has run on Linux with the dispatcher run through a real sudo rule.

One test, `crates/p-robe/tests/stage1.rs` (`test-verbs` feature), run in the
`check` checkout: `cargo test -p p-robe --features test-verbs --test stage1`.
Needs `ssh-keygen`, a built `target/debug/pledge`, and a directory where Unix
sockets bind (`/tmp/claude/`). Three runs in a row passed (4.5 s each) after the two cases were added.

## What is real, what is not

Real: `pledge serve` (keys in files, a fresh state directory, the person on its
standard input), `pledge keys create`, `pledge agents start` (the bundle it
writes), `pledge agents withdraw`, `pledge history --verify`, the control socket
(`agents.start` without `agents.delivered`), the real `ssh-keygen`. From `p_act::pact`:
its bundle parser (`Bundle::parse`), its catalogue built from this service's
`tools/list` (`Catalogue::build`), its composer and in-process signer
(`call_once`, which signs the call and builds the `tools/call` with
`_meta`), so the call and its members are exactly what `pact` sends. From this
crate: the service core, the MCP layer (`Mcp::handle`), `probe setup` for the
service's key and certificate (certified by a throwaway host key that pledge's
`config.json` names), the used-identifier store, the client of `service.sock`.

Not real: the HTTP between `pact` and `probe` (a `Transport` that calls
`Mcp::handle` in-process and reads the SSE the layer writes), **sudo** (the verb
runs in the test process as a caller that is root, `InProcess`; the
`--within` rule is the dispatcher's own code), and the person (answers written
to pledge's standard input).

The crate now has a library (`src/lib.rs`, package `p_robe`); `main.rs` is thin
and `tests/stage1.rs` uses the library, so the unit tests run once.

## Cases, and what the agent was told against what the record says

| # | Case | The agent was told | pledge's record |
|---|---|---|---|
| 1 | `test echo`, default delegation | done, rc 0, `approval=automatic` | approved |
| 2 | `test peak` (top of disruption), person says yes, presence check | done, `approval=confirmed` | approved |
| 3 | `test peak`, person declines | declined | declined |
| 4a | `test read` of a link under `open/` | done, the file's text | approved |
| 4b | the link replaced between the service's rating and the dispatcher's opening | refused / not-allowed (exact `dispatcher-refused`: `--within`), nothing read | approved |
| 5 | the identical `tools/call` posted again | refused / invalid (exact `call-used`, our store) | no new entry |
| 6 | a signed call that went nowhere, its request submitted twice by hand | (unavailable: held) | one entry, **the same approval bytes** for both submissions |
| 7 | second delegation withdrawn with `agents withdraw`, then a call | refused / not-allowed (`pledge:delegation-withdrawn`) | refused, `delegation-withdrawn`; event `delegation-withdrawn` by `person` |
| 8 | a delegation issued by `agents.start` on the control socket and never delivered, then a call | refused / not-allowed (`pledge:unknown-delegation`) | refused, `unknown-delegation` (a pending delegation is not one this pledge answers for); event `delegation-not-delivered` when the connection ends (never `delegation-issued`, never `delegation-withdrawn`: the designer's decision after the first run) |
| 9 | deadline 3 s, dialog open, nobody answers | expired (`expired-by-pledge`) | expired |
| 12 | five parameters of 450 bytes: each within 512, together over 2000 characters | refused / invalid (`pledge:not-showable`) | refused, `not-showable` |
| 10 | the agent goes away (the model's cancel) while the dialog is open | nothing: no answer is written to a client that left | **cancelled**; the verb did not run |
| 11 | `pledge serve` killed and started again while a request is open | unavailable (`no-route`), not submitted again | **no entry** for the open request; after the restart the same bytes submitted by hand are asked about again and approved; the same call through the service is `call-used` (our store); a new call is done |

`pledge history --verify` succeeded (the chain verifies), the record
holds no `PRIVATE KEY`, and the nine request entries are in the order above.
`pact` dropped none of this service's tools; its catalogue has `test_echo`,
`test_peak`, `test_read` and `sys_kit`.

## The two cases added afterwards, expectations first

Case 10, expected before running (`service-sock.md` section 4, `approval-connections.md`
2 and 3.4): the service's connection closes, which cancels; pledge closes the
dialog and records `cancelled`; no approval; the verb does not run. **Held:**
the record's last request entry became `cancelled` within the poll, the
dispatcher's log shows no new `peak`.

Case 11, expected before running (`service-sock.md` sections 4 and 6): the service sees the
connection end, tells the agent `unavailable`, and does not submit again; a
killed pledge cannot write, so the open request has no entry; after the restart
pledge holds nothing for it (only `approved` and `declined` are stored), so the
same bytes submitted by hand are asked about again; the service's store refuses
the same call. **All held**, including that the chain still verifies after the
kill and that the delegation of the first agent still signed after the restart.

## Where the programs did not fit on first contact

**One, and it was mine.**

1. **A call that expires was recorded `cancelled`, not `expired` (case 9).**
   At the deadline the service answered the agent and closed its connection to
   `service.sock` in the same second, in which pledge's own clock also says the
   deadline has passed. A closed connection cancels (`service-sock.md` section
   4, `approval-connections.md` section 2), so pledge recorded `cancelled`.
   Who is right: `doc/approvals.md` R7 and section 6 ("each of the three
   watches the deadline itself", "pledge records the request as expired"), and
   `approval-connections.md` 3.6 (the holder of a request watches the
   deadline itself and forgets it at it): the record should say `expired`, so
   the service must not cancel by closing at the deadline. **Fixed in
   `crates/p-robe/src/pledge.rs`** (commit `b88e5a8` on `agent/p-robe`, merged
   into `check`): after the deadline the service keeps the connection for up
   to 2 seconds and takes pledge's own `expired`; an approval that arrives in
   that time is too late and is not acted on; then it closes. The agent hears
   `expired` at most 2 seconds after the deadline (the stream keeps it alive
   meanwhile). The unit tests of p-robe (119, with the feature) pass with it.
   Not changed in pledge or p-act. (A request the service closes on at once
   **before** the deadline, because the agent went away, is still `cancelled`,
   as it should be.)

**Not a misfit, but worth stating:**

2. **The record and the agent can differ, rightly.** Case 4b: pledge records
   `approved` (it approved what it was shown, at the rating the service
   signed) and the agent is told `refused / not-allowed`, because the
   dispatcher's own rating, made where the file is opened, was above it. R12
   records what pledge did; nothing in the record says the service then
   refused. A person reading `pledge history` sees an approval for a call that
   did not run. Whether pledge should learn of it (a later event) is a design
   question for the designer; today the service's own log
   (`exact=dispatcher-refused`) is the only trace.
3. **A dialog still open after its deadline.** Case 9 was put last on purpose:
   I did not test whether the dialog of an expired request keeps reading
   pledge's standard input and so takes the next scripted answer. Nothing here
   shows it does; nothing shows it does not.

**Things that fitted without a change**, each with the section that says it
should: the bundle's line 1 and key block and certificate line, read by
`pact`'s parser (`pact.md` section 2; `approvals.md` section 10); `pact`'s
catalogue accepting this service's tool descriptions, schemas and names
(`agent-to-service.md` section 5); the flat `_meta` keys
`procession/call` and `procession/call_sig` plus `progressToken` (no
`procession/` key besides those two); the service's request verifying under
the host key pledge's configuration names, with the certificate `setup` made
(`approval-formats.md` sections 4 and 7); pledge accepting the service's
`submit`, its `answer` carrying no clearance (stage 1); the person's name the
same in the certificate, pledge's configuration and the service's
(`PersonKeys { person }`); pledge's reason codes mapped by the closed list
(`delegation-withdrawn`, `unknown-delegation`) to what the agent is told; pledge's
store of answers giving the same approval bytes for the same request.

## Not covered by this run

- Real HTTP, TLS, the SSE head and keepalives over a socket (the layer was
  exercised in process: the transport reads the stream it wrote), and sudo.
- A client that cancels (`CancelToken`) mid-wait against the real pledge.
- A restart of pledge or of the service with requests open, against the
  real pledge (the fake covered it in p-robe's own tests).
- Keys of type ECDSA P-256; the broker (stage 2); Linux (everything here ran on macOS).
