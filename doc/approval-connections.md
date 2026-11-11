# Approvals - connections (draft)

Who sends what to whom, over which connection, in the approval system
([`approvals.md`](approvals.md), whose terms this document uses; the signed
documents are in [`approval-formats.md`](approval-formats.md)). Three hops in
the design carry a request or its answer, and they are **one exchange** on
three transports:

| Stage | Hop | Sends `submit` | Sends `answer` | Who connects | Specified in |
|---|---|---|---|---|---|
| 1 | service to pledge, `service.sock` | the service | pledge | the service | `crates/p-ledge/proposals/service-sock.md`, until it is a section here |
| 2 | service to broker | the service | the broker | the service | section 4 |
| 2 | broker to pledge | the broker | pledge | pledge | section 5 |

This document is the home of the exchange itself (section 3) and specifies the
two broker transports (sections 4 and 5), with everything the pledge
connection carries besides requests: sign-in, delegations, withdrawals,
blocks, certificates, group names, a signed document the broker only carries.
Not here: agent to service (MCP over HTTP; `approval-formats.md` section 9) and
the Unix-socket transport of stage 1.

Status: a draft, written by the p-age agent, reconciled with p-ledge's and
p-robe's sides, and decided by the designer in its open points as of
2026-11-11 (section 9 says which). The designer has read sections 1, 2 and 9
in full and decided the rest on summaries. Nothing implements it. It was checked against
`crates/p-age/SPEC.md` ("What it must not be able to do") and against the table
"Who checks what" of `approvals.md` section 5; section 7 gives the result,
message by message. Numbers are proposals, like those of `approvals.md`
section 7.

## 1. Principles

- **The same as the formats.** What is signed is bytes: a message that carries
  a signed document carries its bytes and the signature beside it, and nobody
  re-creates them. A document or a signature carried inside a message is always
  the base64 (standard alphabet, padded) of its exact bytes; for a signature, of
  its armoured bytes (`approval-formats.md` section 2). A receiver decodes
  first and refuses what is not base64. Strings, times, hashes and "unknown
  members make a message invalid" are the rules of `approval-formats.md`
  section 2.
- **Two kinds of object, marked differently.** A *signed document* (a clearance,
  the connection document, the standing) has `v` and is versioned with its
  namespace. An *unsigned message* (everything that travels on a line) has
  `schema_version` (a number, `1`) and `type`. A message may carry a signed
  document; the message's `schema_version` and the document's `v` are
  independent.
- **A "no" carries no signature** (`approval-formats.md` section 5). What the
  broker says in its own name and that matters is signed with the broker's key.
- **TLS on both broker transports, TLS 1.3 only.** Nothing that matters relies
  on it: TLS keeps strangers from standing in the broker's place on the network
  and from reading requests. What the signatures do is in section 6.
- **No HTTP.** A TCP connection, TLS, and lines.
- **At-least-once, and the receiver is idempotent.** A message may arrive twice
  (after a reconnect). Messages that matter name their request by its hash.

## 2. What is a transport's, and what is not

A transport decides: how the connection is made and who may make it, framing
beyond "one object per line", **how many requests may be open at once on one
connection**, and what happens to open requests when the connection ends.
Everything in section 3 is the same on every transport. Differences that are
the transport's are listed where they occur:

| Transport parameter | `service.sock` | service to broker | broker to pledge |
|---|---|---|---|
| open requests per connection | 16 | 1 | not limited by the connection (the broker's per-agent and per-person settings limit) |
| a connection that ends | cancels its open requests | does **not** cancel: the request stays to its deadline so that the service can submit it again and attach (section 4); only `cancel` cancels | does not cancel: the broker keeps the requests and delivers them again (section 5) |

## 3. The shared exchange

**This whole section is the exchange**, the same on every transport. Nothing
in it names a socket. Its codec is in the crate `p-act`.

### 3.1 Framing

- One JSON object per line, UTF-8, no byte order mark, `\n` at the end and none
  inside. **A line is at most 96 KiB, on every transport** (a request is at most
  32 KiB, 44 KiB as base64). A line that is longer, or not finished within 10 s
  of its first byte, ends the connection.
- Every object has `schema_version` and `type`. A reader refuses a
  `schema_version` or a `type` it does not know, with an `error` (3.5).
- Unknown members make a message invalid.
- Strings: the rules of the formats (no control characters, no bidirectional
  marks).
- Codes (`result`, `by`, reasons, errors) are lower-case words with hyphens,
  `[a-z][a-z-]*`, from **closed lists**. **A reader maps a code it does not know
  to `unknown`**, and never passes the received text on. A program puts nothing
  it received into what it sends: no free text exists in this exchange.

### 3.2 `submit`

From whoever hands over a request: a service to pledge (stage 1) or to the
broker, the broker to a pledge.

```json
{"schema_version":1,"type":"submit","request":"eyJ2IjoxLCJ0eXBl...","request_sig":"LS0tLS1CRUdJTiBTU0ggU0lHTkFUVVJFLS0tLS0K..."}
```

| Member | Meaning |
|---|---|
| `request` | the request's bytes, base64, exactly as the service signed them |
| `request_sig` | the service's SSHSIG over them, namespace `request-v1@procession`, base64 of its armoured bytes |

The broker's `submit` to a pledge is the service's, byte for byte, with nothing
of the broker's added. **The request is identified by the hash of its bytes**
(`sha256:...`), computed by whoever needs it; it is not a member, so there is
nothing that could disagree with the bytes. `submit` for a request the receiver
already holds is a repeat: it changes nothing (and may bring back the answer
again, 3.7).

### 3.3 `answer`

From whoever received the `submit` and has an outcome: pledge, and the broker
toward a service. **Once** per request.

```json
{"schema_version":1,"type":"answer","request":"sha256:9c2f...e1","result":"approved","approval":"LS0tLS1CRUdJTiBTU0ggU0lHTkFUVVJFLS0tLS0K..."}
{"schema_version":1,"type":"answer","request":"sha256:9c2f...e1","result":"approved","approval":"LS0t...","clearance":"eyJ2IjoxLCJ0eXBlIjoiY2xlYXJhbmNlIi...","clearance_sig":"LS0t..."}
{"schema_version":1,"type":"answer","request":"sha256:9c2f...e1","result":"declined"}
{"schema_version":1,"type":"answer","request":"sha256:9c2f...e1","result":"refused","by":"broker","reason":"not-entitled"}
{"schema_version":1,"type":"answer","request":"sha256:9c2f...e1","result":"refused","by":"pledge","reason":"ceiling"}
{"schema_version":1,"type":"answer","request":"sha256:9c2f...e1","result":"expired","by":"broker"}
```

| `result` | Other members | Meaning |
|---|---|---|
| `approved` | `approval`: the SSHSIG over the request's bytes, namespace `approval-v1@procession`, base64 of its armoured bytes. From the broker to a service also `clearance`: the clearance's bytes, base64, and `clearance_sig`: its signature, base64 of its armoured bytes | pledge signed. **Information only**: see 3.6. The answer does not say whether the approval is confirmed or automatic; the certificate in it does |
| `declined` | none | the person said no in a dialog. Nothing else is said |
| `refused` | `by` (`pledge` or `broker`), `reason` | a program said no without asking the person |
| `expired` | `by` (`pledge` or `broker`) | the deadline passed with no approval |

A member that does not belong to the `result` makes the answer invalid.

**The clearance members are configuration, never "if present".** A receiver is
set up for one of two cases and refuses the other:

- *clearance required* (a service in stage 2, `result` `approved` only): an
  `approved` without both members is invalid;
- *clearance refused* (a service in stage 1; pledge's answers on every
  transport; the broker reading pledge's answers): an `answer` with either
  member is invalid.

pledge's `answer` is the same bytes toward a service on `service.sock` and
toward the broker. The broker never forwards pledge's answer: it **builds** its
own from the parsed values, so that nothing it received is passed on unparsed
(an unknown reason of pledge's becomes `unknown`), and adds the clearance to an
`approved`. A `declined`, and a `refused` with `by` `pledge`, are built the same way: from
the parsed `result`, `by` and `reason`, with an unknown `reason` as `unknown`.

### 3.4 `cancel`

```json
{"schema_version":1,"type":"cancel","request":"sha256:9c2f...e1"}
```

From whoever submitted, for a request still open: the sender no longer wants an
answer, and no `answer` follows. pledge closes its dialog and records the
request as cancelled. Toward the broker, `cancel`
removes the request from the broker's holdings and is **passed on** to the
pledge it was put to (or removed from its queue if it was not delivered).
A cancelled request is over: the same bytes submitted again are a new request
(and pledge's store of answers, 3.7, holds nothing for it). Whether the end of
a connection also cancels is the transport's (section 2).

### 3.5 `error`

```json
{"schema_version":1,"type":"error","error":"malformed-line"}
```

The sender closes the connection. Nothing is said about the bytes received.
Shared codes: `malformed-line` (not JSON, a member or string that breaks the
rules), `line-too-long`, `unsupported-version`, `unknown-type`,
`too-many-open` (more open requests than the transport allows). The broker's
own, on its transports: `signin`, `blocked`, `superseded`, `busy`, `timeout`
(section 5).

### 3.6 Rules for every receiver

- **Correlation is by the request's hash.** An `answer` or a `cancel` for a
  hash the receiver does not hold is **ignored and logged** (the hash and the
  time, nothing else).
- **A service never acts on `result`.** It acts only by verifying, itself,
  approval and clearance as `approval-formats.md` section 7 and `approvals.md`
  section 5 say. `declined`, `refused` and `expired` it passes on to the agent as
  those and acts on none. A service that never gets an answer answers its agent
  "expired" at the call's deadline by itself (R7).
- **The deadline is the call's.** Whoever holds a request (service, broker,
  pledge) watches it itself and forgets the request at it. The tolerated clock
  difference (60 s) never extends a deadline: a call whose deadline has passed
  is past. It is applied only where a bound is set on how far ahead a deadline
  may be. The broker sends `expired` (`by` `broker`) to the service at the
  deadline if it has nothing else to say. An approval that reaches the broker later is dropped, and the
  answer is `expired`.
- **A request is answered once** by each party that answers. The broker forgets
  a request after its answer (apart from the wait for an `ack`, section 4) or
  its `cancel`; pledge keeps its answer under the rule of 3.7.

### 3.7 Reasons

Every reason is a code of a closed list; a reader maps an unknown one to
`unknown`.

**pledge's reasons** are the list in pledge's specification (one code for each
of its checks). They are not repeated here, except for what matters to the
exchange (below). `blocked` (the person or a key is
blocked at the broker, learned from the standing) joins that list, as a
passing condition.

**A service gets the exact code**, of pledge or of the broker. What a service
tells its agent is coarser; that is p-robe's document, not this one. The
exchange has no notice that a request was shown to the person.

**The broker's reasons** (`by` is `broker`; the first failing check of
`SPEC.md` is the answer):

| `reason` | Check |
|---|---|
| `bad-request` | the request does not parse, or is not signed by a service key that a host of the site certified, or host and service are not the ones the call names (check 1) |
| `deadline` | check 0 of `SPEC.md`: the call's deadline is past, or more than 10 minutes ahead (the tolerated difference applies to the second only). A limit that bounds what the broker holds, not a trust |
| `delegation` | the call is not signed under a delegation that is registered and not ended or withdrawn (check 2). One code for the three: the agent is not told which |
| `person` | the person is not enabled in the site project, or is blocked (check 3). One code |
| `not-entitled` | R10 (check 4): none of the delegation's groups (the extension of its certificate and nowhere else) is a group the person is in and that the service's binding names for this host |
| `too-many-waiting` | the agent already has as many requests waiting as the site allows |
| `busy` | the broker's own limits (section 4) |

**pledge's answer is final until the call's deadline.** pledge keeps its answers
on disk, and the same bytes submitted again get **the same answer again** from
that store, not a new decision:

| Stored, and answered again | Not stored; the same bytes may be submitted again |
|---|---|
| `approved` (the same approval bytes: a signature made in hardware cannot be made again), `declined`, and `refused` for a **verdict**: `unknown-delegation`, `delegation-ended`, `delegation-withdrawn`, `service-mismatch`, `not-showable`, `ceiling`, `malformed`, `deadline-too-far` | `refused` for a **passing condition**: `limit`, `muted`, `unavailable`, `blocked`. It says nothing about the request, only about now |

- The store lives to the call's deadline, not past it.
- A **cancelled** request is over; the same bytes again are a new request.
- The call's identifier is **used** once pledge approved or the person
  declined. A *different* request under it is refused `call-used`. A declined
  call is **not put to the person again**: the same bytes get `declined` again.
- The broker holds no such store (its only memory of an answer is the wait
  for an `ack`, section 4): a repeated `submit` reaches pledge again whenever the
  broker delivers it again, and pledge answers it from the store.

## 4. Service to broker

The transport of the exchange between a service and the broker.

**Connection.** The service opens a TLS connection to the broker and checks the
broker's TLS certificate against the site's TLS root (section 8). There is no
client certificate and no sign-in: the request's signature is what identifies
the service. The broker treats the connection as nobody's until the request on
it verifies.

**One request per connection**, in this order:

1. The service sends `submit` within 10 s of connecting. A second `submit` on the
   connection is answered with `error` `too-many-open`, and the connection is
   closed.
2. The broker checks (`SPEC.md`, "For a request from a service") and either
   answers `refused` at once, or holds the request (section 5) and later sends
   its `answer`, once.
3. The connection stays open until the answer or the deadline (about 10 minutes at
   most). After the answer the service sends `{"schema_version":1,"type":"ack","request":"..."}`
   so that the broker may drop the answer it held; the broker closes.
   A service that wants to give up sends `cancel` and closes.

**A broken connection does not cancel.** The request's bytes are the service's to
keep until the deadline. If the connection breaks, or the broker restarts, the
service submits **the same bytes** again:

- a request the broker still holds is not checked again for the limit and not
  put to the pledge again; the new connection takes the old one's place (the
  old one is closed with `superseded`) and gets the answer;
- one it no longer holds (it restarted) is a new request, checked as one.

The broker keeps requests in memory only (section 5, "Reconnect"). A restart
loses what waited, and the services' resubmissions put it back; nothing of it
is on disk.

**An answer that was not delivered.** An approval that came back while the
service's connection was gone has nowhere to go. The broker keeps the answer **in
memory** until the service's `ack` or the deadline, whichever is first, so that
the resubmission receives it; then it forgets it. This is the one place where
the broker holds an approval; the designer accepted it and `SPEC.md` says so
("What it keeps"). It is memory only, never on disk, never past the deadline.
An approval is not a secret and is of use only to the service whose request it
signs. Without it a lost connection costs the person a second dialog.

**Limits** (the port is open to anyone who can reach it): a bounded number of
connections per source address and in total; the signature is checked after the
cheap checks (size, parse, deadline, host and service known), so that a
stranger's line costs little; the number of `ssh-keygen` runs at once is
bounded, and above it the answer is `refused` `busy`.

## 5. Pledge to broker

### Connection and sign-in

pledge opens a TLS connection to the broker whenever the machine is awake and
checks the broker's TLS certificate as a service does. It signs in with the
person's connection key, with an SSHSIG over a document, so that the key is
used as every other key in the system is and the broker needs no second
mechanism (a client certificate would need a second form of key and a second
CA).

```json
{"schema_version":1,"type":"challenge","nonce":"q3V0w9h1..."}
```

The nonce is 32 random bytes, base64. pledge answers with a message that
carries a **connection document**, a signed document of the system:

```json
{"schema_version":1,"type":"signin","doc":"eyJ2IjoxLCJ0eXBlIjoiY29ubmVjdGlvbiIs...","doc_sig":"LS0tLS1CRUdJTiBTU0ggU0lHTkFUVVJFLS0tLS0K..."}
```

where `doc` is the bytes of

```json
{"v":1,"type":"connection","person":"jan","nonce":"q3V0w9h1...","tls":"Zk0r..."}
```

| Member | Meaning |
|---|---|
| `person` | who signs in: a name as the site project has it |
| `nonce` | the one the broker sent on this connection |
| `tls` | 32 bytes exported from this TLS connection (RFC 5705, label `EXPORTER-procession-connection-v1`, no context), base64. It ties the signature to this connection, so that it cannot be carried to another |

Namespace `connection-v1@procession`; the key is the person's connection key, a
plain key, not certified (`approvals.md` section 5 certifies the two approval
keys only). Key types are Ed25519 and ECDSA P-256, as for every key
(`approval-formats.md` section 3.1); the broker refuses a sign-in with another.
The broker verifies against the connection key the site project has for
`person` and checks nonce and `tls`. There is no time in the document:
freshness is the nonce, which the broker made for this connection and accepts
once, for 30 s by its own timer. On success:

```json
{"schema_version":1,"type":"ready"}
```

then, in this order: the **standing** (below), a carried document if it holds
one, then every request that waited (below). On failure: `error` with `signin`
(or `blocked` for a person or a key that is blocked, after the signature
verified), and close.

A person has one live connection per connection key. A second sign-in with the
same key closes the first with `superseded`.

**What the sign-in is for**: it decides who is sent the requests of a person (so a
stranger cannot read them) and whose withdrawals the broker takes from
this connection. It is not proof that an approval is the person's: that is the
approval's own certificate, checked by the service. A thief with the connection
key (no presence check) can read requests and withdraw delegations; it cannot
approve, and cannot make a delegation: a certificate that registers must have
been signed by the person's delegation key (below).

### What goes from the broker to pledge

**Requests** are `submit` (3.2), as the service submitted them. pledge checks
everything of its own (`p-ledge/SPEC.md` section 4): call, delegation, deadline,
request signature under `<service>@<host>`, and the person (`unknown-delegation`
for a call whose person is not this pledge's). That the broker checked as well is
not a reason to skip any of it. pledge answers with `answer` (3.3).

**The standing**, in the broker's own name. One message that says, completely
and every time, what the broker holds for this person: no increments, so a missed
message cannot leave pledge with a half view, and a reconnect needs nothing but
sending it again.

```json
{"schema_version":1,"type":"notice","doc":"eyJ2IjoxLCJ0eXBlIjoic3RhbmRpbmciLCJ0byI6ImphbiIs...","doc_sig":"LS0tLS1CRUdJTiBTU0ggU0lHTkFUVVJFLS0tLS0K..."}
```

with `doc` the bytes of

```json
{"v":1,"type":"standing","to":"jan","nonce":"q3V0w9h1...","n":0,"blocked":false,"blocked_keys":[],"withdrawn":["SHA256:Qm3..."],"certificates":["ssh-ed25519-cert-v01@openssh.com AAAAIHNzaC1lZDI1NTE5LWNlcnQtdjAxQG9wZW5zc2guY29t... jan:confirmed"],"groups":["ops","rt"]}
```

| Member | Meaning |
|---|---|
| `to` | the person |
| `nonce` | the nonce of the sign-in this connection began with: the standing is for this connection and no other |
| `n` | a counter: `0` in the first standing after the sign-in, rising by one with each later one on the same connection. pledge accepts a standing only on the connection it was made for (its `nonce` is that connection's) and only if `n` is greater than the last one it accepted, so a repeated or older one changes nothing |
| `blocked` | an administrator blocked the person |
| `blocked_keys` | fingerprints of this person's keys an administrator blocked, `SHA256:...` as `ssh-keygen -l` prints them |
| `withdrawn` | identifiers of delegations an administrator withdrew and that have not ended. The broker forgets an ended one |
| `certificates` | the person's current certificates for the approval keys, as the issuer (whoever holds the site CA's key) made them and the site's data gave them to the broker (optional, may be empty) |
| `groups` | the names of the person's groups, from the part of the broker's data that is refreshed separately (optional, may be empty) |

Namespace `broker-v1@procession`, signed with the broker's key. It is a new
namespace on purpose: the broker's key also signs clearances, and a signature of
the one must never verify as the other. pledge accepts a standing only if it
verifies as `broker`, `to` is its own person, `nonce` is this connection's and
`n` is higher; otherwise it ignores it and records that. **No clock is
involved.** A standing carried off a connection and shown on another carries
the wrong nonce.

How pledge uses it:

- `blocked`, `blocked_keys`, `withdrawn` (delegations are known by their
  identifier, the SHA-256 fingerprint of the agent's public key as
  `ssh-keygen -l` prints it, `SHA256:...`, here, in the register and in
  `withdraw`): it stops asking and signing for the
  person, for that key, for those delegations, at once, and refuses what is
  waiting (`blocked`, `delegation-withdrawn`). These only restrict. The absence of
  one, in a *newer* standing, lifts it.
- `certificates`: pledge accepts a certificate **only** after verifying it
  against the site CA's key itself, for its own key and the right name
  (`<person>:confirmed` or `<person>:automatic`). The broker's signature on the
  standing is not what makes a certificate good; the CA's is. The broker does not
  renew or issue anything: it carries what it was given.
- `groups`: only to offer them to the person when they start an agent. They
  decide nothing: R3 is enforced by the broker's R10 at every request. The
  broker's data for them is refreshed separately, on a timer, from the site
  project or a directory, and the broker does not know which. If a site has none,
  `groups` is empty and nothing else changes.

The broker sends a new standing whenever any of these changes (an
administrator's block, a withdrawal, new data, including a refresh of the group
memberships), and always at sign-in. **Nothing in it depends on how often the
site's data is converged, and nothing scheduled does**: what an administrator does
at the broker reaches a connected pledge at once, and a pledge that was away gets
it before its first request.

**Signed documents the broker did not sign.** The connection must be able to
carry a document that someone else signed and the broker cannot alter. The one
that exists is the list of hosts' keys (`approval-formats.md` section 6.1, a
draft, stage 3), signed by the issuer with the site CA's key itself (not a certified key).

```json
{"schema_version":1,"type":"carried","namespace":"hosts-v1@procession","doc":"eyJ2IjoxLCJ0eXBlIjoiaG9zdHMi...","doc_sig":"LS0tLS1CRUdJTiBTU0ggU0lHTkFUVVJFLS0tLS0K..."}
```

The broker holds the latest one it was given, byte for byte, and sends it after
the standing at every sign-in and whenever it gets a new one. It parses nothing
of it beyond what it needs to store it, and the broker's signature is not on it.
pledge verifies it with a plain line, `hosts namespaces="hosts-v1@procession"
<the site CA's public key>`, under the name `hosts`, and ignores one that does
not verify, one with a `namespace` its own code does not know, and one whose
`at` is not later than that of the list it holds. The newest wins; a list does
not expire (`approval-formats.md` section 6.1). In stage 2 pledge reads hosts from its own
configuration and the broker carries no such document; the message exists so
that stage 3 changes no protocol. **Tempting:** a pledge that treats a host key as
good because the broker sent it. It is good only if the CA's signature verifies.

### What goes from pledge to the broker

pledge's `answer` (3.3) for each request, and `cancel` (3.4) for one it no
longer wants (the broker sends `cancel` to pledge, never the reverse). The other messages
are bound to the connection, and none is signed except what is a signature by
nature (the approval inside an `answer`).

- **`answer`.** For `approved` the broker builds the service's `answer` with its
  clearance: `{"v":1,"type":"clearance","request":"<hash>","at":"<now>"}`
  (formats section 6), signed with the broker's key in `clearance-v1@procession`.
  `at` is when the approval came back. The clearance is over the request's hash
  and says nothing of the approval. For the other results it builds the
  corresponding `answer` with `by` `pledge`.
- The request must be one the broker put to **this connection's person** and
  still holds; others are ignored and logged (3.6). After the answer the broker
  forgets the request and, apart from the wait for an `ack` (section 4), the
  approval.
- **What the broker checks of an approval**: that `approval` decodes to an
  armoured SSHSIG (`p-act`: `looks_armoured`) and that the key that signed is
  not one of the person's blocked keys, read from the certificate inside the
  signature. Both are plain reading, not verification: an approval with a forged
  certificate would be refused by the service. It does **not** verify the
  approval and never writes "approved" for it in its log (it writes "approval
  returned"): that word is the service's to say, and a log or an answer that said
  it would invite a service to rely on it. The log holds hash, times, person,
  host, service and result code; no parameters, no claim.

**Delegations.**

```json
{"schema_version":1,"type":"delegation","cert":"ssh-ed25519-cert-v01@openssh.com AAAA... jan"}
```

`cert` is the agent's certificate, the text of the public certificate. What
authorises a delegation is the certificate itself: it is signed by the person's
delegation key, with a presence check at the issuing. The broker reads and checks
it with `p-act`, against the **person's delegation key from the site project**:
the issuer is that key and no other, the rules are those of
`approval-formats.md` section 3.1 (the person as the only principal, the groups
only in `groups@procession`, no other extension, no critical option, Ed25519 or
ECDSA P-256), and the validity is at most 24 hours. It registers the delegation
under its identifier, the SHA-256 fingerprint of the agent's public key, with the
person, the end and the groups read from the certificate (`src/register.rs`).
What pledge says about groups is never used; there is no such member.
Registering a certificate that is known **changes nothing**: a withdrawn
delegation stays withdrawn, an ended one stays ended.

The registration is authenticated by the sign-in and by nothing else; there is no
second signature. The answer is
`{"schema_version":1,"type":"registered","delegation":"SHA256:..."}` or
`{"schema_version":1,"type":"not-registered","delegation":"SHA256:...","reason":"..."}`
(reasons, a closed list: `bad-certificate`, `too-long`, `not-yours`, `blocked`).

**Withdrawals.**

```json
{"schema_version":1,"type":"withdraw","delegation":"SHA256:Qm3..."}
```

The broker ends the delegation if it is this person's. It stops passing on
requests under it, and the requests of it that are waiting are answered `refused`,
`delegation`. A withdrawal only restricts, which is why the sign-in is enough to
take it.

**Keeping the connection.** pledge sends `{"schema_version":1,"type":"ping"}`
every 30 s while it sends nothing else; the broker closes a connection that was
silent for 90 s (`error` `timeout`).

### Reconnect, and requests that waited

- The broker holds, per person, the requests that passed its checks and have
  not been answered, **in memory**, each until its deadline. It puts one to the
  pledge when the pledge is connected, and keeps it as waiting until the answer
  comes, a `cancel` arrives or the deadline passes, whether or not it wrote it to
  a connection: a write into a connection whose machine fell asleep is not a
  delivery.
- **On every sign-in** the broker sends the standing, a carried document if any,
  and then **all** waiting requests as `submit`, in the order they arrived,
  **again**, including those it had written to the old connection. A request
  whose deadline has passed is not sent and not kept.
- **pledge's side is idempotent** (3.7): a request it already knows by hash is
  not shown again; if it holds a stored answer, it sends that answer again; if it
  is asking the person, it does nothing. A request it refused for a passing
  condition is decided anew. The refusal `call-used` is for a *different* request
  under a call's identifier that was approved or declined.
- pledge reconnects with a delay of 1 s, doubled up to 60 s, with jitter, and at
  once when the network or the sleep state changes. Nothing carries over: every
  connection signs in anew.
- The per-agent limit counts requests that are waiting (not answered, not
  expired), whether or not delivered. A `submit` of one the broker already holds
  does not count twice.

## 6. Who signs, who verifies

In the manner of `approval-formats.md` section 7. `<person>`, `<service>`,
`<host>` are filled in from what is being verified.

| Message | Signed by | Namespace | Verified by | Under the name | Against |
|---|---|---|---|---|---|
| `submit` (`request`, `request_sig`), on all three hops | the service's key, certified by its host's key | `request-v1@procession` | the broker **and** pledge (on `service.sock`: pledge) | `<service>@<host>`, from the call inside (`<service>` is the catalogue type's name; one of a type per host) | the host's public key |
| `signin` (`doc`, `doc_sig`: the connection document) | the person's connection key | `connection-v1@procession` | the broker | `<person>` | the person's connection key, site project |
| `answer`'s `approval` | the person's confirmed or automatic approval key, certified by the site CA | `approval-v1@procession` | **the service** (the broker only reads it) | `<person>:confirmed` or `<person>:automatic` | the site CA's key |
| `answer`'s `clearance`, `clearance_sig` | the broker's key, certified by the site CA | `clearance-v1@procession` | the service | `broker` | the site CA's key |
| `carried` (the list of hosts' keys, stage 3) | the issuer, with the site CA's key itself | `hosts-v1@procession` | pledge | `hosts` (a plain line, not `cert-authority`) | the site CA's key |
| `notice` (`doc`, `doc_sig`: the standing) | the broker's key, certified by the site CA | `broker-v1@procession` | pledge | `broker` | the site CA's key |
| a certificate in the standing | the site CA | (a certificate) | pledge | its own key and `<person>:confirmed` / `:automatic` | the site CA's key |
| `delegation`'s `cert` (a certificate, not a signature) | the person's delegation key | (a certificate) | the broker, with `p-act` | the person, as its only principal | the person's delegation key, site project |
| the messages themselves, and `answer` without approval (`declined`, `refused`, `expired`), `cancel`, `withdraw`, `ping`, `ack`, `registered`, `not-registered`, `challenge`, `ready`, `error` | nobody | none | nobody | none | TLS and, on pledge's connection, the sign-in |

Allowed-signers lines (`namespaces` are what keeps one document from
verifying as another):

```
# the broker, for a connection
<person> namespaces="connection-v1@procession" <the person's connection public key>
# services, for approvals and clearances (approval-formats.md section 7: two lines)
*:confirmed,*:automatic cert-authority,namespaces="approval-v1@procession" <the site CA's public key>
broker cert-authority,namespaces="clearance-v1@procession" <the site CA's public key>
# pledge, for what the broker says in its own name
broker cert-authority,namespaces="broker-v1@procession" <the site CA's public key>
# the broker, for a call (as pledge does)
<person> cert-authority,namespaces="call-v1@procession" <the person's delegation public key>
# pledge, for the list of hosts' keys (stage 3): plain, the CA's key itself
hosts namespaces="hosts-v1@procession" <the site CA's public key>
```
```
# each signature is base64-decoded to its armoured bytes first
ssh-keygen -Y verify -f allowed -I <person> -n connection-v1@procession -s signin.sig < connection
ssh-keygen -Y verify -f allowed -I broker -n broker-v1@procession -s notice.sig < standing
ssh-keygen -Y verify -f allowed -I hosts -n hosts-v1@procession -s hosts.sig < hosts
```

The services' lines for the site CA (formats section 7) list
`approval-v1@procession` and `clearance-v1@procession` each under its own
names and **not** `broker-v1@procession`; pledge's line for the site CA lists
`broker-v1@procession` and neither of those two. A verifier writes only the
namespace it is verifying. So a standing never verifies as a clearance, and the broker's key
cannot be made to say anything to a service that it did not say as a
clearance.

Names that the site CA must never certify for a person, in addition to those
of the formats: `broker` and `hosts`. `broker-v1@procession` and
`connection-v1@procession` are on no service's line.

## 7. Checked against the specification

Each message was read for two questions: what must the receiver not believe
because it came from the broker, and could the message tempt an
implementation to believe it.

**"What it must not be able to do" (SPEC)**

- *Release an action.* A service acts only on an approval that verifies with
  the site CA's key under `<person>:...`. No message gives the broker a way
  to produce one: it holds no such key, and `answer`'s `result` is
  information only (3.6). **Tempting:** a service that reads
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
- *Put a foreign request in front of a person.* The `submit` toward pledge
  carries nothing of the broker's, and pledge repeats every check (R6, R8), including
  `unknown-delegation` for a request that is for another person. **Tempting:** pledge
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
| delegation registered, not ended, not withdrawn (broker, pledge) | broker: refusal `delegation`; pledge: `unknown-delegation`, `delegation-ended`, `delegation-withdrawn`; withdrawals by `withdraw` and `standing.withdrawn`, which add to pledge's own record |
| call names this service, deadline (service, pledge) | not the broker's. The broker's check 0 only bounds what it holds |
| identifier not used (pledge) | pledge only; its stored answers (3.7) make a re-delivery harmless |
| request signed by a certified service, names agree (broker, pledge) | `bad-request`; both verify the same bytes under the same name |
| person enabled, not blocked, R10 (broker) | `person`, `not-entitled`; no other message gives pledge a way to decide these |
| limits on asking (pledge) | pledge's; the broker's per-agent count is the site's setting |
| mode from rating and ceilings (pledge) | not here: the request carries the rating, pledge decides |
| approval over this request, by the person (service) | the broker does not check it (section 5); it is in `answer` as bytes, which the broker only decodes |
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

**Two anchors, each for one purpose** (`approvals.md` section 5). The site CA's
key says **who signed what**: persons, the broker, the list of hosts' keys. The
TLS root, or on a site without a certificate authority a pinned certificate of
the broker, is only for **reaching the broker**: it keeps a stranger from
standing in the broker's place on the network, and decides nothing that is
signed. An SSH CA key cannot verify an X.509 server certificate, so they are two
small files that the provisioning writes.

## 9. Open, decided, and for p-act

**Decided by the designer, followed here:**

- G1: `connection-v1@procession` with the TLS binding, and `broker-v1@procession`
  with one always-complete standing, are in. `delegation-v1` and a proof by the
  agent's key are not: the certificate authorises a delegation (section 5).
- G2: pledge's answer is final to the deadline, from a store on disk (3.7).
- G3: the broker holds an answer in memory until `ack` or the deadline (section 4).
- G4: the deadline is check 0 (`deadline`, 3.7). G5: two anchors (section 8).
- G6: the certificate's person and groups (`approval-formats.md` section 3.1).
- G8: no clock; the standing is tied to the connection by nonce and counter.
- G10, G11: `cancel` in the exchange; `schema_version` and `v` (section 1).

**Open:**

- **How group memberships reach the broker on a site with a directory.** Here
  only that they are a separately refreshed part of its data.
- **G9. Several devices per person** (`approvals.md` section 9). The sign-in names
  the person and a key; requests go to the one live connection of the person. A
  second device needs a rule (all? the first to answer?) and a connection key per
  device. Not designed, not closed off.
- **G12. Settings** on the service port (section 4) and a total per person on
  what the broker holds: their values are not set here.
- **The dependency choice** (section 8) is with the owner.

**What `p-act` needs for this** (the codec for section 3 lives there): the types
and the bounded line reader for `submit`, `answer`, `cancel`, `error`, the
closed code lists with `unknown`; the clearance members as configuration;
parsers for the connection document and the standing; reading and checking an
agent's certificate (issuer, section 3.1 rules, validity, its identifier as
`SHA256:...`); the fingerprint of the key behind a signature, for blocks (G7).

**Section 3 is the shared exchange** and is written to be lifted as it stands:
`submit`, `answer`, `cancel`, `error`, the reasons, the rules for every receiver.
The transports are the table of section 2, section 4 and section 5.
