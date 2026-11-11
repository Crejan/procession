# Approvals - connections (proposal)

Who sends what to whom, over which connection, in the approval system
([`approvals.md`](approvals.md), whose terms this document uses; the four
signed documents are in [`approval-formats.md`](approval-formats.md)).
Three connections exist in the design; this document specifies two of them:

- **(3) service to broker**: a service puts a request to the broker and
  receives approval and clearance, or a refusal, a decline or "expired".
- **(2) pledge to broker**: a person's pledge holds one connection open and
  receives requests; sends approvals, declines, refusals, new delegations and
  withdrawals; and receives what the broker says in its own name.

Not here: (1) agent to service (MCP over HTTP; the open point in
`approval-formats.md` section 9) and the stage-1 socket `service.sock` of
pledge, which another proposal specifies. Section 3 says which part of this
document is meant to be shared with it.

Status: a proposal. Nothing implements it. It was checked against
`crates/p-age/SPEC.md` ("What it must not be able to do") and against the
table "Who checks what" of `approvals.md` section 5; section 7 gives the
result, message by message. Numbers are proposals, like those of
`approvals.md` section 7.

## 1. Principles

- **The same as the formats.** What is signed is bytes: a message that
  carries a signed document carries its bytes (base64, standard alphabet,
  padded) and the signature beside it, and nobody re-creates them. Strings,
  times, hashes and "unknown members make a message invalid" are the rules of
  `approval-formats.md` section 2.
- **One JSON object per line**, UTF-8, `\n` at the end, none inside. A line is
  at most 96 KiB (a request is at most 32 KiB, 44 KiB as base64). A longer
  line closes the connection.
- **Every message has `v` and `type`.** `v` is `1`. The workspace's
  `schema_version` is the version of a tool's `--format json` output; the
  signed documents of the approval system already use `v`, and these messages
  carry such documents, so they use `v` as well. A reader refuses a `v` it
  does not know, and a `type` it does not know, with an `error` message
  (section 2) and closes.
- **A message that carries a "no" carries no signature**, as in
  `approval-formats.md` section 5. A message from the broker that matters
  is signed with the broker's key.
- **TLS on both, TLS 1.3 only**, and nothing in this protocol relies on it
  for anything that is signed: TLS keeps strangers from standing in the
  broker's place on the network and from reading requests. What the signatures
  do is in section 6.
- **No HTTP.** Both connections are a TCP connection, TLS, and lines.
  Nothing in them needs routes, headers or content negotiation.
- **At-least-once, and the receiver is idempotent.** A message may arrive
  twice (after a reconnect). Every message that matters names its request by
  hash (`sha256:...` of the request's bytes), so a repeat is recognised.

## 2. Messages in common

| `type` | From | Meaning |
|---|---|---|
| `error` | either | the sender closes the connection and says why: `reason` (a code, below), optional `detail` (a string, at most 200 characters; shown, never acted on) |
| `ping` | pledge | still here; sent every 30 s while nothing else is |

`error.reason`: `bad-message` (not JSON, unknown `type` or member, too long,
a string that breaks the rules), `bad-version`, `signin` (the sign-in did not
verify; deliberately one code for an unknown person, a wrong key and a stale
nonce), `blocked` (sent only after a signature verified), `superseded` (a
newer connection of the same person), `busy` (limits), `timeout`.

The reasons for a refusal (section 3) have their own list; both lists are
lower-case words with hyphens, `[a-z][a-z-]*`, at most 32 characters.

## 3. The exchange: a request, and the answer

This is the part that does not depend on the transport. A **submit** goes in
and one **answer** comes out, or (a stage-1 `service.sock`, a test, a later
transport) the same two messages on another stream. p-robe has one client for
both.

**`submit`**, service to whoever answers (broker, or pledge in stage 1):

```json
{"v":1,"type":"submit","request":"eyJ2IjoxLCJ0eXBl...","sig":"-----BEGIN SSH SIGNATURE-----\nU1NIU0lH...\n-----END SSH SIGNATURE-----\n"}
```

| Member | Meaning |
|---|---|
| `request` | the request's bytes, base64 |
| `sig` | the service's signature over those bytes (`request-v1@procession`) |

**`answer`**, back, once, for the request named by its hash:

```json
{"v":1,"type":"answer","request":"sha256:9c2f...e1","result":"approved","approval":"-----BEGIN SSH SIGNATURE-----\n...","clearance":"eyJ2IjoxLCJ0eXBlIjoiY2xlYXJhbmNlIi...","clearance_sig":"-----BEGIN SSH SIGNATURE-----\n..."}
{"v":1,"type":"answer","request":"sha256:9c2f...e1","result":"declined"}
{"v":1,"type":"answer","request":"sha256:9c2f...e1","result":"refused","by":"broker","reason":"not-entitled"}
{"v":1,"type":"answer","request":"sha256:9c2f...e1","result":"refused","by":"pledge","reason":"above-ceiling","detail":"rating secret is above the ask ceiling"}
{"v":1,"type":"answer","request":"sha256:9c2f...e1","result":"expired","by":"broker"}
```

| `result` | Other members | Meaning |
|---|---|---|
| `approved` | `approval`: the armoured SSHSIG over the request's bytes. `clearance`: the clearance's bytes, base64, and `clearance_sig`: its signature. Both only from the broker; in stage 1 there is no clearance and the two members are absent | the person's machine signed. **Information only**: see below |
| `declined` | | the person said no in a dialog. No reason, no text |
| `refused` | `by` (`broker` or `pledge`), `reason`, optional `detail` | a program said no without asking the person |
| `expired` | `by` (`broker` or `pledge`) | the deadline passed before an approval came |

A member that does not belong to the `result` makes the answer invalid.

**What a service does with an answer.** It acts on `approved` only by
verifying, itself, approval and clearance as `approval-formats.md` section 7
and `approvals.md` section 5 say; the word `approved` is never the reason. It
passes `declined`, `refused` and `expired` on to the agent as those, and
acts on none of them. An answer that is not `approved` but carries an
approval is invalid. A service that never gets an answer answers its agent
"expired" at the call's deadline by itself (R7).

**Refusal reasons of the broker** (`by` is `broker`; the first failing check
of `SPEC.md` is the answer):

| `reason` | Check |
|---|---|
| `bad-request` | the request does not parse, or is not signed by a service key that a host of the site certified, or host and service are not the ones the call names (check 1) |
| `deadline` | the call's deadline is past, or further away than 10 minutes plus the tolerated difference. Not in `SPEC.md`'s list; see the report |
| `delegation` | the call is not signed under a delegation that is registered and not ended or withdrawn (check 2). One code for all three: the agent is not told which |
| `person` | the person is not enabled in the site project, or is blocked (check 3). One code |
| `not-entitled` | R10 (check 4) |
| `too-many-waiting` | the agent already has as many requests waiting as the site allows |
| `busy` | the broker's own limits (section 4) |

**Refusal reasons of pledge** are for p-ledge's specification to list; a first
set, taken from the checks in its section 4: `not-mine` (the call is not
signed under a delegation this pledge issued, or it ended or was withdrawn;
also a request for another person), `replayed`, `service-mismatch`,
`bad-call`, `not-showable`, `limit`, `muted`, `above-ceiling`, `blocked`.
`detail` from pledge may contain text from the request: whoever logs an
answer logs the code and never the detail (the broker: SPEC, "no action
parameters in its log").

**The deadline is the call's.** Nobody adds a time. Whoever holds a request
(broker, pledge, service) watches the deadline itself and forgets the request
at it; the broker sends `expired` to the service at the deadline if it has
nothing else to say; an approval that reaches the broker later is dropped, and
the answer is `expired`.

## 4. Service to broker

**Connection.** The service opens a TLS connection to the broker and checks the
broker's TLS certificate against the site's TLS root (section 8). There is no
client certificate and no sign-in: the request's signature is what identifies
the service. The broker therefore treats the connection as nobody's until a
request on it verifies.

**One request per connection**, in this order:

1. The service sends `submit`. The broker waits at most 10 s for the line.
2. The broker checks (`SPEC.md`, "For a request from a service") and either
   answers `refused` at once, or sends

   ```json
   {"v":1,"type":"accepted","request":"sha256:9c2f...e1","delivered":false}
   ```

   `delivered` says whether the pledge was connected and the request was put
   to it. It is information for the service's log. Later `answer`, once.
3. The connection stays open until the answer or the deadline (at most about
   10 minutes). After the answer the service sends `{"v":1,"type":"ack","request":"..."}`
   and the broker closes. A service that wants to give up closes.

**Reconnect.** The request's bytes are deterministic: the service holds them
until the deadline. If the connection breaks, or the broker restarts, the
service submits **the same bytes** again. The broker recognises the hash:

- a request it is still holding is not checked again for the limit and not
  put to the pledge again; the new connection takes the old one's place (the
  old one is closed with `superseded`) and gets the answer;
- one it no longer holds (it restarted) is a new request, checked as one.

The broker keeps requests in memory only (section 5, "Reconnect"). A broker
restart therefore loses what waited, and the services' resubmissions put it
back; nothing of it is on disk.

**An answer that was not delivered.** An approval that came back while the
service's connection was gone has nowhere to go. The broker keeps the answer
**in memory** until the service's `ack` or the deadline, whichever is first,
so that the resubmission receives it; then it forgets it. This is the one place
where the broker holds an approval, and it is a question for the designer
(`SPEC.md` says "no approval at all"); without it a lost connection costs the
person a second dialog that pledge cannot ask for (R5). Section 9, G3.

**Limits** (the connection is open to anyone who can reach the port): a
bounded number of connections per source address and in total; one `submit`
and nothing else per connection; the signature is checked after the cheap
checks (size, parse, deadline, the host and service known) so that a
stranger's line costs little; the number of `ssh-keygen` runs at once is
bounded, and above it the answer is `busy`.

## 5. Pledge to broker

### Connection and sign-in

pledge opens a TLS connection to the broker whenever the machine is awake and
checks the broker's TLS certificate as a service does. It signs in with the
person's connection key, with an SSHSIG over a document, so that the key is
used as every other key in the system is, and the broker needs no second
mechanism (a client certificate would need a second form of key and a second
CA).

```json
{"v":1,"type":"challenge","nonce":"q3V0w9h1...","at":"2026-11-11T15:04:05Z"}
```

The nonce is 32 random bytes, base64. pledge answers with a **connection
document**, a fifth signed document in the manner of the four:

```json
{"v":1,"type":"signin","doc":"eyJ2IjoxLCJ0eXBlIjoiY29ubmVjdGlvbiIs...","sig":"-----BEGIN SSH SIGNATURE-----\n..."}
```

where `doc` is the bytes of

```json
{"v":1,"type":"connection","person":"jan","nonce":"q3V0w9h1...","tls":"Zk0r...","at":"2026-11-11T15:04:06Z"}
```

| Member | Meaning |
|---|---|
| `person` | who signs in: a name as the site project has it |
| `nonce` | the one the broker sent on this connection |
| `tls` | 32 bytes exported from this TLS connection (RFC 5705, label `EXPORTER-procession-connection-v1`, no context), base64. It ties the signature to this connection, so that it cannot be carried to another |
| `at` | pledge's time; the broker refuses a difference of more than 60 s |

Namespace `connection-v1@procession`; the key is the person's connection key,
a plain key, not certified (`approvals.md` section 5 certifies the two
approval keys only). The broker verifies against the connection key the site
project has for `person` and checks nonce, `tls` and `at`. On success:

```json
{"v":1,"type":"ready"}
```

then, in this order: the **standing** (below), then every request that waited
(below). On failure: `error` with `signin` (or `blocked` for a person or a key
that is blocked, after the signature verified), and close. The nonce is good
once, for 30 s.

A person has one live connection per connection key. A second sign-in with the
same key closes the first with `superseded`.

**What the sign-in is for**: it decides who is sent the requests of a person
(so a stranger cannot read them, G6) and whose withdrawals the broker takes
from this connection. It is not proof that an approval is the person's:
that is the approval's own certificate, checked by the service. A thief with
the connection key (no presence check) can read requests and withdraw
delegations; it cannot approve, and cannot register a delegation, which needs
the person's delegation key (below).

### What goes from the broker to pledge

**Requests.**

```json
{"v":1,"type":"request","request":"eyJ2IjoxLCJ0eXBl...","sig":"-----BEGIN SSH SIGNATURE-----\n..."}
```

The service's request, exactly as the service submitted it; no hash and
nothing else (what pledge can compute, it computes, so that two values cannot
disagree). It carries no signature of the broker. pledge checks everything of
its own (`p-ledge/SPEC.md` section 4): call, delegation, deadline, request
signature under `<service>@<host>`, the person, `not-mine` if the call's
person is not this pledge's. That the broker checked as well is not a reason
to skip any of it.

**The standing**, in the broker's own name. This is one message that says,
completely and every time, what the broker holds for this person: no
increments, so a missed message cannot leave pledge with a half view, and a
reconnect needs nothing but sending it again.

```json
{"v":1,"type":"notice","doc":"eyJ2IjoxLCJ0eXBlIjoic3RhbmRpbmciLCJ0byI6ImphbiIs...","sig":"-----BEGIN SSH SIGNATURE-----\n..."}
```

with `doc` the bytes of

```json
{"v":1,"type":"standing","to":"jan","at":"2026-11-11T15:04:07Z","serial":12,"blocked":false,"blocked_keys":[],"withdrawn":["SHA256:Qm3..."],"certificates":["ssh-ed25519-cert-v01@openssh.com AAAAIHNzaC1lZDI1NTE5LWNlcnQtdjAxQG9wZW5zc2guY29t... jan:confirmed"],"groups":["ops","rt"]}
```

| Member | Meaning |
|---|---|
| `to` | the person |
| `at`, `serial` | when, and a counter that rises with each standing the broker makes for this person. pledge accepts a standing only if `(at, serial)` is greater than that of the last one it accepted, so an old one that is sent again changes nothing |
| `blocked` | an administrator blocked the person |
| `blocked_keys` | fingerprints of this person's keys an administrator blocked |
| `withdrawn` | fingerprints of delegations an administrator withdrew and that have not ended. The broker forgets an ended one |
| `certificates` | the person's current certificates for the approval keys, as the site's roll-out gave them to the broker (optional, may be empty) |
| `groups` | the names of the person's groups (optional, may be empty) |

Namespace `broker-v1@procession`, signed with the broker's key. It is a sixth
document type and a new namespace on purpose: the broker's key also signs
clearances, and a signature of the one must never verify as the other. pledge
accepts a standing only if it verifies as `broker`, `to` is its own person and
the order is right; otherwise it ignores it and records that.

How pledge uses it:

- `blocked`, `blocked_keys`, `withdrawn`: it stops asking and signing for the
  person, for that key, for those delegations, at once, and refuses what is
  waiting with `blocked` or `not-mine`. These only restrict. The absence of
  one, in a *newer* standing, lifts it.
- `certificates`: pledge accepts a certificate **only** after verifying it
  against the site CA's key itself, for its own key and the right name
  (`<person>:confirmed` or `<person>:automatic`). The broker's signature on the
  standing is not what makes a certificate good; the CA's is. The broker
  does not renew or issue anything: it carries what the roll-out gave it.
- `groups`: only to offer them to the person when they start an agent.
  They decide nothing: R3 is enforced by the broker's R10 at every request.
  With a directory, group memberships are not in the site project (open at
  fundament); then `groups` is empty and nothing else changes.

The broker sends a new standing whenever any of these changes (an
administrator's block, a withdrawal, a roll-out that brought new data), and
always at sign-in. **Nothing in it depends on the roll-out being frequent**:
what an administrator does at the broker reaches a connected pledge at once,
and a pledge that was away gets it before its first request.

### What goes from pledge to the broker

All of these are bound to the connection; none is signed, except what is a
signature by nature (the approval, the delegation's proof).

```json
{"v":1,"type":"approval","request":"sha256:9c2f...e1","sig":"-----BEGIN SSH SIGNATURE-----\n..."}
{"v":1,"type":"decline","request":"sha256:9c2f...e1"}
{"v":1,"type":"refuse","request":"sha256:9c2f...e1","reason":"above-ceiling","detail":"rating secret is above the ask ceiling"}
```

- `approval`: `sig` is the SSHSIG over the request's bytes, namespace
  `approval-v1@procession`. The broker answers the service as `approved` with
  its clearance (below). `decline` and `refuse` go to the service as `declined`
  and as `refused` with `by` `pledge` and the reason and detail as sent.
- The request must be one the broker put to **this connection's person** and
  still holds. Others are ignored. After the answer the broker forgets the
  request and the approval.
- **What the broker checks of an approval**: that `sig` is an armoured SSHSIG
  (`p-act`: `looks_armoured`) and that the key that signed is not one of the
  person's blocked keys, read from the certificate inside the signature. Both
  are plain reading, not verification: an approval with a forged certificate
  would be refused by the service. It does **not** verify the approval and
  never writes "approved" for it in its log (it writes "approval returned"):
  that word is the service's to say, and a log or an answer that said it
  would invite a service to rely on it.
- **The clearance.** `{"v":1,"type":"clearance","request":"<hash>","at":"<now>"}`
  (formats section 6), signed with the broker's key in `clearance-v1@procession`.
  `at` is when the approval came back. The clearance is over the request's
  hash and says nothing of the approval.

**Delegations.**

```json
{"v":1,"type":"delegation","cert":"ssh-ed25519-cert-v01@openssh.com AAAA... jan","proof":"-----BEGIN SSH SIGNATURE-----\n..."}
```

`proof` is a signature by the agent's own (certified) key over the bytes of
`cert`, namespace `delegation-v1@procession`, made by pledge when it created the
key, before it handed it over. The broker verifies it with `ssh-keygen -Y verify`
against the person's delegation key from the site project, the way it
verifies a call: that checks the certificate without the broker having a
certificate parser, and shows that the certificate belongs to a key somebody
holds. It then reads the delegation's fingerprint, end and groups from the
certificate and registers them (`src/register.rs`). It refuses a validity
longer than 24 hours. The answer is `{"v":1,"type":"registered","delegation":"SHA256:..."}` or
`{"v":1,"type":"not-registered","delegation":"SHA256:...","reason":"..."}`
(reasons: `bad-proof`, `too-long`, `not-yours`, `blocked`). Registration does
not rely on the sign-in, so the connection key alone cannot register one.

**Withdrawals.**

```json
{"v":1,"type":"withdraw","delegation":"SHA256:Qm3..."}
```

The broker ends the delegation if it is this person's. It stops passing on
requests under it, and the requests of it that are waiting are answered
`refused`, `delegation`. A withdrawal only restricts, which is why the sign-in
is enough to take it.

### Reconnect, and requests that waited

- The broker holds, per person, the requests that passed its checks and have
  not been answered, **in memory**, each until its deadline. It puts one to
  the pledge when the pledge is connected, and keeps it as waiting until the
  answer comes or the deadline passes, whether or not it wrote it to a
  connection: a write into a connection whose machine fell asleep is not a
  delivery.
- **Silence is detected by the broker**: a connection on which nothing came
  for 90 s is closed (pledge sends `ping` every 30 s). Its requests stay
  waiting.
- **On every sign-in** the broker sends the standing and then **all** waiting
  requests, in the order they arrived, **again**, including those it had
  written to the old connection. A request whose deadline has passed is not
  sent and not kept.
- **pledge's side must be idempotent**, and that needs one thing of
  pledge's specification (section 9, G2): a request it already knows by hash
  is not shown, not signed again, not refused as a replay (R5): if it already
  answered, it sends that answer again, byte for byte (a signature made with a
  key in hardware is not reproducible), which it must keep until the
  deadline; if it is asking the person, it does nothing. R5's refusal is for
  a *different* request under a call's identifier that it already signed for.
- pledge reconnects with a delay of 1 s, doubled up to 60 s, with jitter,
  and at once when the network or the sleep state changes. It does not carry a
  session over: every connection signs in anew.
- The per-agent limit counts requests that are waiting (not answered, not
  expired), whether or not delivered. A resubmission of one the broker already
  holds does not count twice.

## 6. Who signs, who verifies

In the manner of `approval-formats.md` section 7. `<person>`, `<service>`,
`<host>` are filled in from what is being verified.

| Message | Signed by | Namespace | Verified by | Under the name | Against |
|---|---|---|---|---|---|
| `submit` (the request) | the service's key, certified by its host's key | `request-v1@procession` | the broker, **and** pledge | `<service>@<host>`, from the call inside | the host's public key |
| `signin` (the connection document) | the person's connection key | `connection-v1@procession` | the broker | `<person>` | the person's connection key, site project |
| `request` to pledge | the service, as above; the broker adds nothing | `request-v1@procession` | pledge | `<service>@<host>` | the host's public key |
| `approval` | the person's confirmed or automatic approval key, certified by the site CA | `approval-v1@procession` | **the service** (the broker only reads it) | `<person>:confirmed` or `<person>:automatic` | the site CA's key |
| `answer` with a clearance | the broker's key, certified by the site CA | `clearance-v1@procession` | the service | `broker` | the site CA's key |
| `notice` (the standing) | the broker's key, certified by the site CA | `broker-v1@procession` | pledge | `broker` | the site CA's key |
| a certificate in the standing | the site CA | (a certificate) | pledge | its own key and `<person>:confirmed` / `:automatic` | the site CA's key |
| `delegation` (`proof`) | the agent's key, certified by the person's delegation key | `delegation-v1@procession` | the broker | `<person>` | the person's delegation key, site project |
| `decline`, `refuse`, `withdraw`, `ping`, `accepted`, `ack`, `registered`, `not-registered`, `error`, `answer` without clearance | nobody | none | nobody | none | TLS and, on pledge's connection, the sign-in |

Allowed-signers lines (`namespaces` are what keeps one document from
verifying as another):

```
# the broker, for a connection
<person> namespaces="connection-v1@procession" <the person's connection public key>
# pledge, for what the broker says in its own name
broker cert-authority,namespaces="broker-v1@procession" <the site CA's public key>
# the broker, for a delegation's proof (as for a call)
<person> cert-authority,namespaces="call-v1@procession,delegation-v1@procession" <the person's delegation public key>
```
```
ssh-keygen -Y verify -f allowed -I <person> -n connection-v1@procession -s signin.sig < connection
ssh-keygen -Y verify -f allowed -I broker -n broker-v1@procession -s notice.sig < standing
ssh-keygen -Y verify -f allowed -I <person> -n delegation-v1@procession -s proof.sig < cert
```

The services' line for the site CA (formats section 7) lists
`approval-v1@procession,clearance-v1@procession` and **not** `broker-v1@procession`;
pledge's line for the site CA lists `broker-v1@procession` and neither of those
two. So a standing never verifies as a clearance, and the broker's key
cannot be made to say anything to a service that it did not say as a
clearance.

Names that the site CA must never certify for a person, in addition to those
of the formats: anything that would verify as `broker`.

## 7. Checked against the specification

Each message was read for two questions: what must the receiver not believe
because it came from the broker, and could the message tempt an
implementation to believe it.

**"What it must not be able to do" (SPEC)**

- *Release an action.* A service acts only on an approval that verifies with
  the site CA's key under `<person>:...`. No message gives the broker a way
  to produce one: it holds no such key, and `answer`'s `result` is
  information only (section 3). **Tempting:** a service that reads
  `"result":"approved"` and acts; a service that accepts a clearance without
  an approval (the clearance's `request` is a hash and says nothing of
  approval). Both are defects.
- *Say who a person is.* The sign-in names the person for routing only. The
  person's certificates in the standing are verified by pledge against the CA;
  the broker's signature does not make them good. The broker verifies no
  approval, so nothing at the broker can later be read as "the broker found
  this to be the person's". **Tempting:** pledge accepting a certificate or a
  person's name because it came in a signed standing; the broker logging
  "approved". Neither is allowed.
- *Put a foreign request in front of a person.* The `request` message carries
  nothing of the broker's, and pledge repeats every check (R6, R8), including
  `not-mine` for a request that is for another person. **Tempting:** pledge
  skipping the call's check because "the broker checked check 2". The broker's
  checks are a filter in front of pledge's, never a substitute.

**"What it is trusted for"**

- *Blocks and withdrawals* travel in the standing and only restrict; a taken
  over broker can lift them by sending a newer standing. That is in the
  threat model ("blocks are gone") and not new. pledge's own register of
  delegations stays what decides which calls it accepts: `withdrawn`
  can only add.
- *Limits and queue:* memory only, to each deadline. A taken over broker can
  hold requests back (refuse everything: in the model) but cannot alter one:
  the service's signature covers it.

**"Who checks what"**

| Check of the table | Where it is in this proposal |
|---|---|
| delegation registered, not ended, not withdrawn (broker, pledge) | broker: refusal `delegation`; pledge: `not-mine`; withdrawals by `withdraw` and `standing.withdrawn`, which add to pledge's own record |
| call names this service, deadline (service, pledge) | not the broker's. The broker's `deadline` check only bounds what it holds (section 9, G4) |
| identifier not used (pledge) | pledge only; section 5 asks that a re-delivery not be a replay |
| request signed by a certified service, names agree (broker, pledge) | `bad-request`; both verify the same bytes under the same name |
| person enabled, not blocked, R10 (broker) | `person`, `not-entitled`; no other message gives pledge a way to decide these |
| limits on asking (pledge) | pledge's; the broker's per-agent count is the site's setting |
| mode from rating and ceilings (pledge) | not here: the request carries the rating, pledge decides |
| approval over this request, by the person (service) | the broker does not check it (section 5); it is in `answer` as bytes |
| approval key fits the rating (service) | the service's; the broker cannot know |
| at the moment of acting: deadline, single use (service) | the service's |
| clearance fresh and by `broker` (service) | the clearance is a separate signed document; `at` is when the approval came back |
| what is the broker's word is signed by its key (pledge) | the standing, in its own namespace |

## 8. Dependencies

Chosen conservatively; none is added yet. A line-based protocol over TLS
needs a TLS implementation, an async runtime and a JSON parser, and nothing
else.

| Crate | Choice | Why |
|---|---|---|
| `tokio` 1 | features `rt-multi-thread`, `net`, `io-util`, `time`, `sync`, `macros`, `signal` | what the workspace already uses elsewhere; two kinds of connection and many waiting requests are what an async runtime is for. No `tokio-util`: a line reader with a limit is a few lines on `AsyncBufReadExt` |
| `rustls` 0.23 | `default-features = false`, features `ring`, `std`; **TLS 1.3 only** (no `tls12`) | memory-safe, no system library, both ends are ours so there is nothing to be compatible with. Also gives `export_keying_material` for the sign-in's binding |
| `tokio-rustls` 0.26 | `default-features = false`, feature `ring` | the glue, with nothing else |
| `ring` (through rustls) as provider, **not** `aws-lc-rs` | | `aws-lc-sys` needs a C and CMake toolchain; `ring` has the shorter build and the smaller tree. Both are in the registry here |
| `rustls-pki-types` | feature `std` | reading PEM certificate and key files (its PEM support replaces `rustls-pemfile`, which is no longer maintained) |
| `serde`, `serde_json`, `base64` | | as `p-act` has them; the messages are parsed with `serde_json` and the signed bytes handled as in `p-act` |
| dev: `rcgen` 0.14 (`ring`, `pem`) | | a test root and server certificate |

Not chosen: `axum`, `hyper`, `tower`, `h2` (HTTP: no use for it here, and
`atticus-server` uses axum for its old protocol, which is HTTP); `sqlx` and
any database (the broker's storage is the register, blocks and a log, and the
queue is memory); `native-tls` and `openssl` (a system library, and different
behaviour per machine); `tokio-tungstenite` (WebSocket: a framing this
protocol does not need). The register and the blocks go to a file the broker
rewrites atomically; that is not a dependency either.

**Mutual TLS is not used** for pledge: the connection key is an SSH key, the
sign-in is the system's own mechanism, and a person's key in key hardware
would otherwise need an X.509 form of it too.

**What is missing in this sandbox.** Nothing found: with the list above,
`cargo generate-lockfile --offline` in a scratch directory outside the
worktree resolves all 78 packages from `~/.cargo/registry` (tokio 1.54.1,
rustls 0.23.46, tokio-rustls 0.26.6, rustls-webpki 0.103.16, ring 0.17.14,
rustls-pki-types 1.15.1, serde_json 1.0.154, rcgen 0.14.10 for tests). That
resolved the versions; it did **not** build them. `ring` compiles C and
assembly through `cc`, which was not tried. Anything beyond that list
(`tokio-util`, `rustls-pemfile`, `aws-lc-rs`) was not needed.

**TLS trust.** The broker's certificate comes from the site's TLS root, an
X.509 root. `approvals.md` section 5 says pledge and services hold "one trust
anchor for persons and broker, the site CA's key"; an SSH CA key cannot verify
an X.509 server certificate. Proposal: pledge and service hold two things,
the site CA's SSH public key (signatures) and the site's TLS root (the
server certificate, by name), both small files that the provisioning writes.
Section 9, G5.

## 9. Open, and where this proposal does not fit the specifications

Each with a proposal; none is settled here.

- **G1. A new document and three new namespaces.** `connection-v1`,
  `broker-v1` and `delegation-v1`, besides the four of the formats; the
  connection document's type is the "connection" the formats' list of
  namespaces in `approvals.md` section 5 already names. `broker-v1` has several
  uses inside it (`type: standing`), against the rule of one namespace per
  document type; one document that carries everything the broker says to a
  pledge, signed once, is what makes the reconnect trivial. Proposal: keep it,
  and let the `type` be inside the signed bytes. `p-act` needs the new
  namespaces and parsers for `connection`, `standing` and the `answer`
  messages (pledge, broker and service parse them all).
- **G2. R5 against a re-delivery** (`approvals.md` R5, `p-ledge/SPEC.md`
  section 4, step 7). pledge "signs for an identifier once"; a request that
  the broker delivers again after a lost connection would be refused as a
  replay, and the approval that was lost with the connection cannot be made
  again. Proposal: pledge keeps, for each request it answered, the answer
  (approval signature, or the decline or refusal) until the deadline, and
  sends it again on a re-delivery; R5 applies to a *different* request under
  the same call identifier.
- **G3. "No approval at all" against delivery** (`SPEC.md`, "What it
  keeps"). The broker holds the answer in memory until the service's
  `ack` or the deadline. Proposal: accept this as the only exception and say so
  in `SPEC.md`, because the alternative is that a broken connection in the
  last second costs a second dialog that R5 forbids. Not on disk, ever.
- **G4. The deadline is not in `SPEC.md`'s list of checks.** The broker
  keeps requests until their deadline, so it needs one and a bound
  (`approvals.md` section 7: more than 10 minutes is refused). Proposal: a
  check 0, `deadline`, beside parsing; it is a limit and not a trust.
- **G5. One trust anchor** (`approvals.md` section 5), see section 8: an SSH CA
  key and a TLS root are two things. Proposal: two files.
- **G6. The agent's certificate: principals.** `approvals.md` section 5 says
  the delegation's certificate carries "the chosen groups as principals";
  `approval-formats.md` section 7 and `p-act` (`signature_person`) take the
  **one** principal as the person, and refuse more. Both cannot hold, and the
  broker needs the delegation's groups for R10 (check 4). Proposal: principal
  = the person only, and the groups in a certificate extension
  (`groups@procession`) that the delegation key signs, so that the groups
  are the person's own narrowing and the broker cannot widen them. Then
  `delegation` needs no `groups` member. The alternative, groups in the
  `delegation` message, makes them an unsigned claim in the broker's register.
- **G7. The key behind a signature.** Blocking a key (SPEC) needs the
  fingerprint of the key that signed an approval or an agent's call, read
  from its certificate; `p-act`'s `Certificate` does not give it. Proposal:
  add it, and the fingerprint as `SHA256:...` as `ssh-keygen -l` prints it.
- **G8. Ordering of the standing** by `(at, serial)` depends on the broker's
  clock not going back across a restart. Proposal: accept; after a restart
  the broker starts `serial` at 0 and `at` is later. If its clock were wrong, pledge
  would ignore standings until the time is past: it fails toward the last
  restriction it knew, which is the safe side for a block and the unsafe one for
  a lifted block. Say so, or add a challenge-bound standing at sign-in.
- **G9. Several devices per person** (approvals.md section 9). The sign-in
  names the person and a key; requests go to the one live connection of the
  person. A second device needs a rule (all? the first to answer?) and a
  connection key per device. Not designed, not closed off: `person` and the
  key are separate in the sign-in.
- **G10. Cancel.** A service that gives up has no message to say so; its
  request waits to the deadline (and the person may be asked about it). A
  `cancel` from the service (pledge closes the dialog) is cheap. Left out: an
  extra message in the part shared with stage 1; to be decided with p-ledge.
- **G11. `schema_version` or `v`**, see section 1. Proposal: `v`.
- **G12. Limits** on the service port (section 4) and a total per person on
  what the broker holds are settings whose values are not set here.

What is **transport-independent** and meant to be shared with pledge's
stage-1 `service.sock` (section 3): `submit` and `answer`, the reasons for a
refusal and the rule that a service never acts on the word `approved`. What is
the broker's own: everything in sections 4 and 5, `accepted`, `ack`, and the
clearance members of `answer`.
