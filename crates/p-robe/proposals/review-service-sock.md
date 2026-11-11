# Review of `service-sock.md`, from the service's side

Reviewer: the p-robe agent. Reviewed: `crates/p-ledge/proposals/service-sock.md`
of the p-ledge worktree (with `record.md` and `control-sock.md` only where they
touch the service). Against: `crates/p-robe/SPEC.md`, "What the service does
with a call", and `agent-to-service.md` (changed in this commit). The decisions
of the designer at `47bb806` are taken as given: a signature travels as the
base64 of its armoured bytes next to the document it belongs to, the person is
the only principal of an agent's certificate, Ed25519 and ECDSA P-256 only,
`service.name` is `probe`, the binding's `groups` are the broker's check.

**Verdict.** `probe serve` can do everything its SPEC requires with these
messages, in stage 1 and, with the additions below, in stage 2. Four changes
I ask for (sections 2, 5, 6), two I advise, and the reason lists differ more
than they should (section 3). Nothing in it makes me trust pledge's word where
the SPEC says I check; one sentence could be read that way (section 5).

## 1. Can the service do its five steps with these messages?

| SPEC step | With `ask`/`answer` | Remark |
|---|---|---|
| 1 checks before asking anybody | no message needed | The service refuses the call itself and never connects |
| 2 sign the request | `ask` carries `request` and `request_sig`, both as the service made them | Fits. Sizes: a call of 16 KiB is about 22 KiB in the request, with `call_sig` under 32 KiB, 43 KiB in base64, under the line limit of 128 KiB |
| 3 send, wait until the deadline | `ask`, then `answer` or the deadline | Fits, see 4 |
| 4 approval is over exactly this request | `approval` is the armoured SSHSIG; the service has the request's bytes and verifies against them, not against anything pledge echoes | Fits, and `answer` carries nothing the service must believe |
| 4 by the person the call's delegation names | the principal of the certificate inside `call_sig` (the only one, formats 3.1), `-I <person>:confirmed` or `:automatic` | Fits. `p-act` reads the principal; the service does not verify the agent's certificate |
| 4 confirmed key for a top rating | decided from the approval's own certificate name, which verifies only under `<person>:confirmed` or `:automatic` | Fits, **because** `answer` does not say which key signed (section 4 of the proposal says so on purpose; keep it) |
| 4 deadline and used identifiers | the service's own clock and store | Not in the protocol, as it should be (section 4 below) |
| 4 clearance | `clearance`, `clearance_sig` in the broker's answer | Stage 2, section 5 below |
| 5 run, answer the agent | not on the socket | |

## 2. Changes I ask for

**A. The service records a call's identifier at `ask`, not when it runs.**
This is a change on my side, not in the proposal, but it settles the
proposal's open question 2 for this service. The SPEC says used identifiers
are kept "until their call's deadline"; I will write the identifier to disk
(flushed) at step 2, before the `ask` leaves. A call, once asked, is then
spent for the service: after `declined`, `expired`, `cancel` or a restart, the
same call is refused `call-used` by the service itself and never reaches
pledge twice. So pledge's "a declined call may be asked again until its
deadline" cannot arise from this service; it can from another sender, and its
muting count is the right answer there. Consequence for the SPEC: "nothing was
run for this call's identifier" (step 4) is the same store.

**B. A stage-2 service requires a clearance by configuration, never by what
the answer contains.** Section 4 says "on `service.sock` nobody sends them, and
a service in stage 1 checks none". Read loosely that invites an
implementation that checks a clearance when one is present. The service needs
a setting fixed at start (`stage`), in stage 2 every `approved` answer
without a valid, fresh clearance is refused, and in stage 1 a clearance that
arrives is ignored and logged. I ask the proposal to say it that way, and the
codec (section 6) to treat a stage-1 answer with `clearance` members as a
protocol error from pledge, since `approved` from pledge never carries them.

**C. The socket's door in section 6 contradicts itself.** The directory is
"only the person owns (mode 0700)", the socket 0600, "a setting adds one group
for services that run under their own account (probe's does)". A group cannot
reach a 0700 directory. With the group the directory needs 0710 (search only,
nothing listable) and the socket 0660. Please state that, and say that
**the service checks the other end too** before it sends anything: the socket's
directory and the socket belong to the configured person's uid, neither is a
symlink, and `SO_PEERCRED` of the connection is that uid. Nothing an impostor
on that path could say would run anything (it cannot sign an approval), but it
could talk the service into denying everything, and an `ask` hands a signed
request, with the call's bytes, to whoever listens.

**D. `unknown ref` in an `answer` is ignored and logged, not an error.** The
service forgets a `ref` when it has answered its agent (at its own deadline,
on a cancel). Pledge's `expired` or a late `approved` for it can still arrive.
It must not close the connection. (A late `approved` is refused by the
service anyway: its deadline has passed. R7.)

Advised, not asked:

- **A `shown` message** (`{"type":"shown","ref":..}` when the dialog is on
  screen). Without it the service cannot tell its agent more than "handed to
  your person's machine": dialogs queue one at a time and an agent waits
  without knowing whether anybody has seen the request. Not needed for
  correctness; I removed "asked" from the progress notifications in
  `agent-to-service.md` because of this.
- **`ping`** (or: connecting is the test). `sys kit` should say whether pledge
  can be reached. A connect and an immediate close do that without a message;
  I will do that unless you prefer a message.

## 3. The reasons, in both directions

Pledge's `refused` reasons (13) against the agent-facing list I proposed in
`agent-to-service.md` (outcomes and reasons). Written as one table; "none"
marks a code with no counterpart on the other side.

| Pledge's `result`/`reason` | My earlier agent-facing code | Now |
|---|---|---|
| `declined` | `declined` / `person-declined` | same; the reason is the service's constant |
| `expired` | `expired` / `no-approval` | same |
| `malformed` | **none** (I had `invalid-call` for what the service refuses) | passed on as `malformed` |
| `unknown-delegation` | **none** | passed on |
| `delegation-ended` | `delegation-ended` | same |
| `delegation-withdrawn` | **none** | passed on |
| `deadline-past` | **none** (`invalid-call`) | passed on, and used by the service for its own check |
| `deadline-too-far` | **none** (`invalid-call`) | passed on, and used by the service |
| `call-used` | `used` | renamed `call-used` everywhere |
| `service-mismatch` | **none** | passed on, logged loudly: it is the service's own installation that is wrong (key, certificate, name), and no agent can fix it |
| `not-showable` | **none** | passed on; the service also checks strings itself (formats section 2) and refuses `invalid-call` first |
| `limit` | `limit` | same (pledge's per-agent limit; the service's own bound answers HTTP 503, section 7 of `agent-to-service.md`) |
| `muted` | `muted` | same |
| `ceiling` | `over-ceiling` | renamed `ceiling` |
| `unavailable` (could not ask or record) | `unavailable` / `no-route` | outcome `unavailable`, reason `pledge-unavailable`; `no-route` stays for "could not connect or the connection broke" |

Codes of mine with no counterpart in pledge's list, and where they come from:

| My code | Why it has no counterpart in pledge's list |
|---|---|
| `invalid-call` | the service refuses before it asks (wrong host or service, unknown verb, arguments the row does not accept) |
| `mismatch` | the HTTP body differs from the signed call; no pledge involved |
| `approval-invalid` | what pledge sent did not verify, or it is an automatic approval for a top rating; the service's own check, and the one that must **not** be pledge's word |
| `not-permitted` | the broker's (person not entitled, or the person's groups not among the binding's `groups`); stage 2, "belongs to the broker's specification" as the proposal says |
| `busy` (HTTP 503, no outcome) | a bound of the service, transport level |

Agreement: I adopt pledge's names verbatim and pass them through
unchanged, so one vocabulary reaches the agent whichever side said no.
Rules for the pass-through (now in `agent-to-service.md`): the service forwards
a `reason` only if it is in the closed list; any other string becomes
`unknown`, and no string received is ever copied into what an agent reads. This
is the proposal's own rule ("a reader treats a `reason` it does not know as
`refused`"), made concrete.

Open question 3 of the proposal (are the reasons an oracle): I accept the fine
list for the person's own agent. `service-mismatch` and `pledge-unavailable`
are operator problems and tell an agent nothing it can use; I would shorten
both to `unavailable` for the agent and keep the detail in the audit line, if
the designer prefers. Not insisting.

## 4. The deadline, a broken connection, a restart

**At the deadline.** The service has its own timer, from the call's
`deadline` as written, with no tolerance toward running (R7: after the
deadline nothing starts). At the deadline without an `answer` it answers its
agent `expired` / `no-approval` at once, and does not wait for pledge's
`expired`. It sends no `cancel` then: pledge watches the deadline itself (R7)
and records `expired`; a `cancel` would make pledge record `cancelled` for
what is an expiry. If the two clocks differ, a dialog may stand a few seconds
beyond the service's deadline; an approval signed in that window arrives for a
`ref` the service has forgotten (change D) and, if it is looked at, fails the
deadline check. Pledge would have recorded it as approved and nothing ran:
that is the one place where pledge's record and the service's differ, and I
ask the p-ledge agent to know it. It cannot cause an action.

**`cancel`.** It is what I asked for, with two reservations. (1) It has no
answer, so the service cannot tell whether pledge closed a dialog or had
already signed. That is fine: the service has recorded the identifier (change
A) and marks the call cancelled, so an `approved` that crosses the `cancel` is
ignored (not run) and the agent has gone. Pledge's record shows `approved` for
something nobody acted on; I suggest pledge records the cancel as an event
beside it. (2) The proposal says a closed connection cancels every open ask.
Good: it makes a crash of the service close its dialogs.

**A broken connection.** EOF, a write error or a write that stalls longer than
5 seconds on pledge's side, or an `error` message: every open ask is answered
`unavailable` / `no-route` at once, the connection is closed, and **the asks
are not sent again**: pledge reserved the identifiers it had signed for, and a
re-ask is a new decision that belongs to the agent with a new call (R11). The
next call connects again, lazily; a failed connect answers `unavailable` /
`no-route` at once, with no retry loop. A line that is not complete within 10
seconds ends the connection; the service does the same to a pledge that
stalls.

**Restart with asks open.** Two cases.
- The service restarts: its connection closes, pledge cancels the dialogs, the
  agents' HTTP connections are gone. On disk are the identifiers (change A), so
  a retried call is `call-used`. Approvals signed in between are lost. Nothing
  runs for a call whose waiter is gone.
- Pledge restarts: as a broken connection. Pledge's store of used identifiers
  survives on its side, the service's on its.
A verb that is already running is not touched by either. There is no replay
and no resume in this design, on purpose.

**Waiting in code.** One reader thread demultiplexes `answer`s by `ref` to
per-call channels; each waiter does `recv_timeout` until its deadline. Blocking
I/O, no runtime, as the proposal intends. The service keeps at most 16 asks
open (the proposal's limit per connection) and answers the next call HTTP 503
rather than provoke `too-many-asks`.

## 5. Where I check and where I would only be told

| Statement in or around the protocol | What the service does |
|---|---|
| `answer` `approved` | verifies the SSHSIG over its own copy of the request; never reads which key from the answer |
| pledge's own checks ("signs only what it shows") | not relied on: the service's checks (rating's top needs the confirmed key, person, deadline, used) are all its own |
| `declined`, `refused`, `expired` | passes them on; they can only lead to no action, which is the safe direction |
| pledge or the broker said `approved` but with a mode `automatic` for a top rating | refused by the service (`approval-invalid`) |
| the broker's clearance | stage 2: verified against the broker's certificate under the site CA, fresh within 60 seconds, over the request's hash (section 2, change B) |
| `reason` | forwarded only from the closed list (section 3) |
| the peer on the socket | checked by the service (change C); pledge's own peer record is information |

One sentence I would reword, besides B: section 5, "A used call identifier is
stored before the approval is signed", is pledge's own guarantee and is good;
but no reader should take it as a reason for the service to skip its own store.
It is two stores by design (the table in `doc/approvals.md` section 5).

## 6. Sections 2 and 8: one `ask`/`answer`, the codec in `p-act`

**Yes, it works for me.** The service sends `ask` and reads `answer` in both
stages; only the end it connects to differs (stage 1: pledge's Unix socket;
stage 2: the broker over TLS, which the service opens outbound as the diagram
of `approvals.md` section 6 shows). One sender, one reader, one set of
reasons: the DRY outcome the proposal argues for, and the code is
blocking `std` only. Four conditions:

1. **Two `answer` shapes, not one with optional members.** The formats refuse
   unknown members. Pledge's `answer` and the broker's (with `clearance`,
   `clearance_sig`) should be two types in `p-act` (or one type and a
   `from_pledge`/`from_broker` reader that refuses what does not belong), so
   the stage-1 rule of change B is enforced by the decoder.
2. **The limit of 16 open asks is per connection and a parameter.** At a site
   one connection carries every agent of every host's service to the broker;
   16 is the stage-1 value for a single person's machine. Name it as the
   transport's.
3. **`Reason` in `p-act` is a closed enum plus `Unknown`**, with its wire
   string; the pass-through of section 3 is then a type, not a convention.
   What is said to an agent (`outcome`, text) stays in p-robe.
4. **Framing is the transport's** (section 10 of the proposal): a TLS stream
   carries the same lines; nothing in the messages depends on a Unix socket
   except peer credentials, which only stage 1 has.

I also ask that `p-act` has the **line reader with the proposal's limits built
in** (128 KiB, 10 seconds from the first byte, unknown members, control
characters), with a clock it is given, so that it can be tested without
sockets.

## 7. Other remarks on the proposal

- **Open question 1** (a fifth outcome, `cancelled`): agreed.
- **Open question 2** (a declined call asked again): moot for this service
  (change A); fine as written for others.
- **Open question 4** (`ref` against `id`): keep `ref`. The service numbers
  asks with a counter per connection.
- **Open question 5** (base64): keep. With the decision of the designer the
  value of `Procession-Call-Signature` is the same string as `request_sig`
  would be for the agent's signature, and is copied, not re-encoded
  (`agent-to-service.md`, section 3).
- **Open question 6** (clock tolerance): agreed as proposed; the service uses
  none towards running, and 60 seconds only for "too far ahead", like pledge.
- **`error`**: it carries no `ref`, so it ends the whole connection. The
  service treats it like a broken connection (section 4).
- **Section 3: `duplicate-ref`.** The service never repeats a `ref` on a
  connection; it uses a counter and starts again at 1 on a new connection.

## What I need from p-ledge and p-act

- p-ledge: C (door and permissions), D (unknown `ref` is not an error for the
  service's side of the exchange; it concerns the proposal's wording only if
  pledge sends an `error` for a `cancel` of an unknown `ref`: please let
  that be silent too), and a record entry for a cancel after an approval.
- p-act: `Ask`, `Answer` (two shapes), `Cancel`, `Reason`, the line reader
  (section 6), and the reading of a call that gives the person's principal.
- The orchestrator: SPEC changes that follow (record the identifier at step 2;
  `stage` as a setting; the reason list), after the designer has seen this.
