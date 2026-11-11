# Proposal: `service.sock`, pledge's Unix-socket transport

Status: a proposal by the p-ledge agent, revised after the p-robe review and
the orchestrator's reconciliation with the p-age agent's connections
proposal. Terms are those of `doc/approvals.md`, section 1. Nothing is built
on it.

## 1. What this document is, and is not

`service.sock` is where a service on the person's machine (stage 1:
`probe serve`, which has no broker) hands pledge a request. The exchange
itself, **`submit`** and **`answer`** with their members, the hash that
correlates them, the `by` of a refusal and the base64 rule, is defined once,
in the connections document (p-age's proposal, section 3, to become
`doc/approval-connections.md`). This document does not define those messages
again. It specifies:

1. the transport: framing parameters and who may connect (sections 2, 3);
2. what pledge does with a submitted request (section 4);
3. pledge's refusal reasons (section 5);
4. the two points where the shared exchange needs pledge to hold state
   (section 6).

Delegations, keys, programs and the record are on `control.sock`
(`control-sock.md`), not here.

## 2. Transport parameters

The framing is the shared exchange's: one JSON object per line, UTF-8, `\n`,
`schema_version` and `type` on every message, no unknown members, signatures
and documents as the base64 of their exact bytes, no free text anywhere. The
parameters of this transport:

| Parameter | Value |
|---|---|
| Stream | a Unix stream socket, blocking I/O, one reader and one writer per connection |
| Line | at most 96 KiB, the same on every transport. A line that is longer, or does not end within 10 seconds of its first byte, ends the connection |
| Requests open per connection | 16. This is a parameter of the transport: a connection of the broker carries more |
| `error` | a protocol violation (`malformed-line`, `line-too-long`, `unsupported-version`, `unknown-type`, `too-many-submits`) is answered with one `error` and the connection is closed. It names no request |

Everything else about the messages (members, `result`, `by`, correlation)
is the connections document's. pledge sends `answer` with `by` `pledge` on
`refused` and `expired`; it never sends `clearance` or `clearance_sig`.

**Stage 1 refuses clearance members; stage 2 requires them.** Which stage a
service is in is a setting fixed at its start, never read from what arrives.
In stage 1 an `approved` answer with `clearance` members is a protocol error
by the sender (pledge never sends them; the decoder refuses them). In stage
2 the service requires them on every `approved` and refuses one without. That
is the service's side; it is stated here because this is where stage 1 lives
(p-robe review, B). It needs two answer shapes in `p-act` (pledge's, and the
broker's with the clearance), so that the decoder enforces it.

## 3. Who may connect

- **Directory and socket.** The socket is in a directory the person owns.
  Without a group setting: directory 0700, socket 0600. With a group setting
  for services that run under their own account (probe's does): directory
  **0710** (the group may search, not list) and socket **0660**, group set to
  that group. A group cannot pass a 0700 directory (p-robe review, C).
  `pledge serve` checks at start: owner is the person, mode is as above, no
  symlink on the path.
- **It is only a door.** Connecting grants nothing: every submitted request
  is checked against pledge's own delegations and host keys (R8). pledge
  records the peer's user and process (`SO_PEERCRED`, `LOCAL_PEERPID`) as
  information and decides nothing by them.
- **The service checks the other end too**, before it sends a request: the
  directory and the socket belong to the configured person's uid, neither is
  a symlink, and the connection's peer credentials are that uid. An
  impostor on the path cannot sign an approval, but could be handed a signed
  request and the call's bytes, or talk the service into refusing
  everything. That check is the service's; this document only says it is
  expected.
- **Reachability test.** A connect followed by an immediate close is a
  test that pledge is there (`sys kit`). pledge treats it as nothing and
  logs nothing beyond a counter.

## 4. What pledge does with a submitted request

In the order of `SPEC.md`, section 4: decode and parse request and call
(`p_act`), check the call under the delegations pledge issued, check the
request against the host keys it knows, check that every field is showable,
apply the limits, derive the mode, sign or ask, then **sign, record, send**.
The record entry is flushed before the `answer` leaves; if it cannot be
written the answer is `refused` / `unavailable` and nothing is signed (no
record, no approval, `record.md`). The call's identifier is stored as used before the approval is signed (section 6). That is pledge's guarantee, and it is not a reason
for a service to skip its own store: the two are separate by design.

- Requests that arrive together are normal: the person sees one dialog at a
  time, the rest wait, each until its own deadline, then `expired`.
- Correlation is by the request's hash, `sha256:` over the decoded bytes,
  which needs no parsing. A second `submit` of the same bytes is recognised by
  it (section 6). There is no `ref` and so no `duplicate-ref`.
- **`cancel`** (by hash, from the sender) closes the dialog of an open
  request and is answered with nothing. A connection that closes cancels all
  its open requests. The record has the request as `cancelled`. A `cancel`
  for a hash pledge does not hold, or whose answer was sent, **is ignored
  and logged**, not an error; so is an `answer` toward a service for a hash
  it does not hold (that is the service's rule, and it is stated in the
  connections document). A `cancel` that arrives after pledge signed does not
  undo it: the entry already says `approved`.
- The service's own deadline: pledge watches the deadline itself and sends
  `expired` (`by` `pledge`) at it. A service answers its agent "expired" at
  the deadline without waiting for that.

## 5. pledge's refusal reasons

`reason` is a code from a closed list, never text; pledge puts nothing it
received into what it sends. A reader treats a code it does not know as a
refusal and nothing more.

| `reason` | Check that failed (`SPEC.md`, section 4) |
|---|---|
| `malformed` | the request or the call in it does not parse |
| `unknown-delegation` | the call is not signed under a delegation this pledge issued (this includes a call for another person) |
| `delegation-ended` | its delegation's validity has passed |
| `delegation-withdrawn` | its delegation was withdrawn |
| `deadline-past` | the call's deadline has passed |
| `deadline-too-far` | more than 10 minutes ahead |
| `call-used` | pledge already signed for this call's identifier (section 6) |
| `service-mismatch` | the request is not signed by a service key that a host pledge knows certified, or host and service are not the ones the call names |
| `not-showable` | a field is too long or holds a control character or a bidirectional mark |
| `limit` | too many requests of this agent are waiting |
| `muted` | the person declined this agent three times within ten minutes |
| `ceiling` | the rating is above the delegation's ask ceiling (mode `refuse`) |
| `unavailable` | pledge could not ask (no terminal, no dialog possible) or could not write the record |

p-age's first set for pledge (`not-mine`, `replayed`, `bad-call`,
`above-ceiling`, `blocked`) differs in names, and p-robe has adopted the
names above in its agent-facing list; the two lists are to be made one by
the reconciliation. `blocked` is the broker's (a person or key blocked);
pledge has no such check on a request. In `p-act` the list is a closed enum
with an `Unknown` for what a reader does not know, with its wire string.

## 6. Pledge's answer is final until the deadline (decided)

Decided by the designer (`doc/approvals.md`, R5): pledge decides on a call's
identifier once. The identifier is **used** as soon as pledge approved or
the person declined, and stays so until the call's deadline. From then:

- the same request bytes again get **the same answer again**, from a store
  on disk, without a second dialog and without a second signature: for
  `approved` the same approval bytes (pledge signs once), for `declined` the
  same `declined`;
- a different request under a used identifier is refused `call-used`;
- a declined call is not put to the person again; the decline counts toward
  muting once.

What is stored under the request's hash until the call's deadline, and what
is not:

| Answer | Stored, and given again | Why |
|---|---|---|
| `approved` | yes, the approval's bytes | a lost connection must not cost a second dialog |
| `declined` | yes | the person has decided |
| `refused`, a verdict: `unknown-delegation`, `delegation-ended`, `delegation-withdrawn`, `service-mismatch`, `not-showable`, `ceiling`, `malformed`, `deadline-too-far` | yes | the same bytes would get the same verdict |
| `refused`, a passing condition: `limit`, `muted`, `unavailable`, and `blocked` (stage 2, the broker's) | no; may be submitted again | the condition may be gone |
| `expired` | the deadline has passed: nothing is held; a submit gets `refused` / `deadline-past`, not stored | |
| cancelled | no: the request is over; the same bytes again are a new request | |

The store is written with the record entry, before the first send: sign,
record, store, send. After the deadline an entry is forgotten. A request
whose dialog is open and is submitted again is left alone (nothing is sent
until there is an answer). `call-used` itself is a verdict for a different
request and is not stored under that request's hash.

**Clock.** The 60 seconds of tolerance never extend a deadline: pledge
refuses as soon as its own clock says the deadline has passed
(`deadline-past`). The tolerance applies only to "more than 10 minutes
ahead" (`deadline-too-far`) and to a certificate whose validity starts in the
near future.

## 7. The p-robe review, point by point

| Point | Decision |
|---|---|
| A. The service records the identifier before it submits | Noted; it is the service's own store. Makes "a declined call asked again" moot for this service; pledge's muting stays for other senders |
| B. Stage is a setting, never "if present"; stage 1 refuses clearance members | Adopted (section 2) |
| C. The door: 0710 / 0660 with a group, the service checks the other end | Adopted (section 3) |
| D. An unknown reference is ignored and logged | Adopted for `cancel` and `answer`, and no `error` is sent for them (section 4); with correlation by hash it is the hash that is unknown |
| `shown` message | Not adopted now. It adds a state and a message that nothing in correctness needs; an agent waiting without knowing whether the dialog is on screen is a user-interface matter. Open for the designer (question 4) |
| `ping` | Not adopted: connect-and-close is the test (section 3) |
| Reasons: one vocabulary, passed through unchanged, closed list | Adopted (section 5); p-robe adopts pledge's names, which is the direction the reconciliation should keep |
| `service-mismatch` and `unavailable` shortened for the agent | The service's choice; pledge's codes stay as they are |
| Two `answer` shapes in `p-act` | Adopted (section 2) |
| 16 open requests a transport parameter | Adopted (section 2) |
| `Reason` a closed enum with `Unknown` in `p-act` | Adopted (section 5) |
| A line reader in `p-act` with the limits built in and a clock it is given | Adopted: 96 KiB, 10 seconds from the first byte, unknown members, control characters. It also lets the transport be tested without a socket |
| `error` carries no reference and ends the connection | Adopted (section 2) |
| A record entry for a cancel after an approval | An approval already answered is recorded `approved`; the cancel is ignored and logged (section 4). A cancel before the approval is `cancelled` |
| Open question 4 (`ref` against the call's id) | Settled by the reconciliation: correlation by the request's hash |
| Open question 6 (clock tolerance) | As proposed: none for pledge's own sign or refuse; 60 seconds only for "too far ahead" |

## 8. Decisions on the earlier open questions

1. `cancelled` is the fifth outcome in the record.
2. Reading A, and one step further (section 6).
3. A declined call is not put to the person again (R5).
4. No `shown` notice in the first version.
5. Exact reason codes go toward a service; what an agent learns is coarse
   and the service's business.
6. The tolerance is as in section 6.
7. The socket's group is a setting with no default.

## 9. Separable from its transport

Sections 4 to 6 say nothing about sockets. Only section 2's parameters and
section 3 are particular to this transport. The broker connection carries
the same `submit` and `answer` with its own framing parameters, which is why
the exchange has one home.
