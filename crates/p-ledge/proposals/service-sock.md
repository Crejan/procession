# Proposal: the protocol on `service.sock`

Status: a proposal by the p-ledge agent, for review by the p-robe agent and
then the designer. Nothing is built on it. Terms are those of
`doc/approvals.md`, section 1. Nothing here changes a signed format
(`doc/approval-formats.md`); it is the unsigned message around them.

## 1. What it is for

A service on the person's machine (stage 1: `probe serve`; it has no broker)
hands pledge a request and gets back one of: an approval, a decline, a
refusal with its reason, or "expired". That is all `service.sock` does.
Delegations, keys, programs and the record are on `control.sock`
(`control-sock.md`).

## 2. One protocol for every hop that carries a request

`doc/approvals.md`, section 6, has three hops that carry a request or its
answer: service to pledge (stage 1), service to broker, broker to pledge
(stage 2). They are the same exchange, so they use the same two messages,
`ask` and `answer`, and stage 2 needs no second protocol:

| Stage | Hop | Sends `ask` | Sends `answer` | Who connects |
|---|---|---|---|---|
| 1 | service to pledge, `service.sock` | the service | pledge | the service |
| 2 | service to broker | the service | the broker, with the clearance added | the service |
| 2 | broker to pledge, the connection pledge holds | the broker | pledge | pledge |

The messages do not depend on who connected: a connection carries `ask`s one
way and `answer`s the other, whichever side opened it. What the broker
connection will carry beyond these (pledge's sign-in, delegations,
withdrawals, blocks, certificates, group names) are further message types in
the same envelope, specified with that connection and signed where trust
needs it. pledge's `answer` is the same bytes on `service.sock` and toward
the broker; only the broker's `answer` to a service has two more members
(section 4).

## 3. Framing, shared with `control.sock`

- A Unix stream socket. One JSON object per line, UTF-8, no byte order mark,
  `\n` ends a line. The workspace convention for machine output.
- Every object has `schema_version` (a number, `1`) and `type`. A reader
  refuses a `schema_version` it does not know. This is not the signed
  documents' `v`: those are signed and versioned with their namespace.
- A line is at most 128 KiB (a request is at most 32 KiB, which is 44 KiB in
  base64). A line that does not end within 10 seconds of its first byte, or
  is longer, ends the connection.
- Unknown members make a message invalid, as in the signed formats.
- Strings carry no control characters or bidirectional marks
  (`approval-formats.md`, section 2). A document or signature carried in a
  message is always the base64 (standard, padded) of its exact bytes, so
  signatures have no line breaks in the line.
- Blocking I/O, one reader and one writer per connection; no runtime is
  needed.

A line that fails these is answered with one `error` and the connection is
closed:

```json
{"schema_version":1,"type":"error","error":"malformed-line"}
```

`error` codes: `malformed-line`, `line-too-long`, `unsupported-version`,
`unknown-type`, `duplicate-ref`, `too-many-asks`. Nothing else is said about
the bytes received.

## 4. The messages

**`ask`**, from whoever hands over a request:

```json
{"schema_version":1,"type":"ask","ref":"7","request":"<base64 of the request's bytes>","request_sig":"<base64 of the armoured SSHSIG>"}
```

- `ref`: chosen by the sender, 1 to 64 characters of `[A-Za-z0-9._-]`, unique
  on the connection among its unanswered asks. It only matches an `answer` to
  its `ask`; it is not the call's identifier and means nothing outside the
  connection.
- `request`: the request's bytes, base64, exactly as the service signed
  them. `request_sig`: its armoured SSHSIG, base64 (standard, padded) of its exact bytes, namespace `request-v1@procession`. Both are
  carried, never rebuilt (`approval-formats.md`, section 1).
- The sender may have any number of asks open up to 16 per connection; the
  seventeenth is answered with an `error`, `too-many-asks`. pledge's own
  limits per agent (`doc/approvals.md`, section 7) are separate and are
  answered with a refusal.

**`answer`**, from pledge, exactly once per `ask` that pledge did not see
cancelled, in any order:

```json
{"schema_version":1,"type":"answer","ref":"7","result":"approved","approval":"<base64 of the armoured SSHSIG>"}
{"schema_version":1,"type":"answer","ref":"7","result":"declined"}
{"schema_version":1,"type":"answer","ref":"7","result":"refused","reason":"call-used"}
{"schema_version":1,"type":"answer","ref":"7","result":"expired"}
```

| `result` | Members | Meaning |
|---|---|---|
| `approved` | `approval` | base64 of the armoured SSHSIG over the request's bytes, namespace `approval-v1@procession`, by the confirmed or the automatic approval key. Which one is in its certificate; the answer does not say, because nothing may act on the answer's word for it |
| `declined` | none | the person said no in a dialog. Nothing else is said, so that an agent learns nothing from how |
| `refused` | `reason` | pledge said no without asking, or could not ask |
| `expired` | none | the call's deadline passed with no approval. Sent at the deadline, by pledge's own clock |

`reason` is a code from a closed list, never free text: an agent will read
what a service passes on, and pledge does not put anything it received into
what it sends.

| `reason` | Check that failed (`SPEC.md`, section 4) |
|---|---|
| `malformed` | the request or the call in it does not parse (`p-act` refused it) |
| `unknown-delegation` | the call is not signed under a delegation this pledge issued |
| `delegation-ended` | its delegation's validity has passed |
| `delegation-withdrawn` | its delegation was withdrawn |
| `deadline-past` | the call's deadline has passed (with the tolerated clock difference of `doc/approvals.md`, section 7, if the designer applies it here: Open questions, 6) |
| `deadline-too-far` | more than 10 minutes ahead |
| `call-used` | pledge already signed for this identifier, or has an ask open for it |
| `service-mismatch` | the request is not signed by a service key that a host pledge knows certified, or host and service are not the ones the call names |
| `not-showable` | a field is too long or holds a control character or a bidirectional mark |
| `limit` | too many requests of this agent are waiting |
| `muted` | the person declined this agent three times within ten minutes |
| `ceiling` | the rating is above the delegation's ask ceiling (mode `refuse`) |
| `unavailable` | pledge could not ask (no terminal, no dialog possible), or could not write the record: no record, no approval |

The broker will add reasons of its own (blocked, not entitled, person not
enabled); they belong to the broker's specification. A reader treats a
`reason` it does not know as `refused` and nothing more.

**`cancel`**, from the sender, optional:

```json
{"schema_version":1,"type":"cancel","ref":"7"}
```

Withdraws an ask that is still open: pledge closes its dialog and sends no
`answer`. A connection that closes cancels all its open asks. pledge
records a cancelled ask (see Open questions, 1).

The broker's `answer` to a service adds `clearance` (the clearance document,
base64, as signed) and `clearance_sig` (its armoured SSHSIG), both base64 next to `approval`. pledge
never sends them and never accepts them. On `service.sock` nobody sends
them, and a service in stage 1 checks none.

## 5. What pledge does with an `ask`

In the order of `SPEC.md`, section 4: parse and check call and request, show
nothing that cannot be shown as it is, apply the limits, derive the mode,
sign or ask, then **sign, record, send**. The record entry is written and
flushed before the `answer` leaves; if it cannot be written, the answer is
`refused` / `unavailable` and nothing is signed (`record.md`). A used call
identifier is stored before the approval is signed.

- Concurrent `ask`s are normal: the person sees one dialog at a time, the
  others wait, each until its own deadline, then `expired`.
- An ask whose request is byte for byte one already open on the connection
  is answered `refused` / `call-used`, not queued twice.
- After a decline the same call may be asked again until its deadline; each
  decline counts toward the muting limit. (Open question, 2.)

## 6. Who may connect

The socket is in a directory only the person owns (mode 0700, checked at
start: owner, mode, not a symlink), the socket mode 0600; a setting adds one
group for services that run under their own account (probe's does). That is
only a door: connecting grants nothing, because every `ask` is checked
against pledge's own delegations and host keys (R8). pledge records the
peer's user and process (`SO_PEERCRED`, `LOCAL_PEERPID`) as information and
decides nothing by them. The service is the one that signed the request.

## 7. A session, for the p-robe agent

```
service                                   pledge
  connect ─────────────────────────────────▶
  {"type":"ask","ref":"1","request":..} ───▶   checks, dialog
  ... the person says yes ...
  ◀──── {"type":"answer","ref":"1","result":"approved","approval":..}
  (the service now checks the approval itself, `approval-formats.md` 7,
   then the deadline and its own used identifiers, and acts)
```

The service watches the deadline itself and answers its agent "expired"
without waiting for pledge's `expired`. If the person's machine is off, or
pledge is not running, `connect` fails and the service refuses the call:
"when in doubt, no".

## 8. Where it lives in code

The codec (these messages, the framing, `reason`) is small and shared by
three programs. *Proposal:* it belongs in `p-act`, next to the signed
documents, as `Ask` and `Answer` types with a line reader and writer.
`approval-formats.md`, section 9, already gives `p-act` the formats; this
adds the unsigned envelope. Until then p-ledge writes it in
`crates/p-ledge/src/` and moves it.

## 9. Open questions for the designer

1. **A fifth outcome.** `doc/approvals.md` R12 lists approved, declined,
   refused, expired. A service that gives up (closes the connection, or
   sends `cancel`) while a dialog is open is none of them. *Proposal:* record
   it as `cancelled` and close the dialog; it is not an answer to anybody.
2. **A declined call asked again.** R5 says an identifier is signed for once,
   which a decline does not break. *Proposal:* allowed until the deadline;
   each decline counts toward muting, so it cannot be used to wear a person
   down.
3. **The reasons given to the agent.** The service passes `reason` on to an
   agent, which is untrusted. A list this fine tells it which of its checks
   fail. *Proposal:* keep it, because the agent is the person's own and
   needs to know it was too late and not too much; coarsen it if the
   designer sees an oracle.
4. **`ref` against the call's identifier.** The call's `id` could serve as
   the reference and save a member, but pledge would have to parse before it
   can refuse, and the broker would need its own for a call it has not
   parsed. *Proposal:* keep `ref`.
5. **Base64 for the request inside the line.** Needed so the bytes are the
   bytes; costs a third. *Proposal:* keep.
6. **The tolerated clock difference** (60 seconds, "all"). It is not said
   which way it tilts for a deadline. *Proposal:* none for pledge's own
   decision to sign or refuse, which uses its own clock and the deadline as
   written, and 60 seconds only when it judges a call's deadline "too far
   ahead".

## 10. Separable from its transport

`ask`, `answer`, `cancel`, `ref` and the reasons (sections 4 and 5) say
nothing about sockets; only section 3 (line framing) and 6 (who may
connect) are specific to a Unix stream. Another transport (the broker's TLS
connection) can carry the same objects with its own framing, and the p-age
agent's connection messages can share the envelope (`schema_version`,
`type`) and these shapes. Section 3's limits are the transport's, the
members are not.
