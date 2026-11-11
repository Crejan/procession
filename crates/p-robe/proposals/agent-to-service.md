# How an agent reaches the service - a proposal

Status: a proposal for the orchestrator and the designer, written against
`doc/approvals.md` (its terms), `doc/approval-formats.md` and
`crates/p-robe/SPEC.md`. Nothing here is built. It settles what
`approval-formats.md` section 9 and `SPEC.md` ("Open") leave open for the
first connection of the system: agent to service. Decided in principle, and
not reopened here: MCP over HTTP, the signed call in a header of each tool
call.

## 1. Who does what on the agent's side

The model that drives an agent cannot sign: the key lives in the sandbox, not
in the model. A small piece of the agent's own runtime, here called the
**signer**, sits between the model's tool calls and the HTTP request. For each
tool call it builds the call (`approval-formats.md` section 3), signs it with
the agent's delegated key, and sends it. The model sees a tool name, its
arguments and an answer; it never sees the key, the identifier or the headers.
The signer is not part of p-robe. It needs an owner (see "What I need").

The signer, not the model, sets `id` (fresh UUID per tool call, never reused,
also not after "expired"), `deadline` (default: now + 2 minutes; the model may
ask for another through the argument `wait_seconds`, at most 600), `service`
(`host` from its configuration, `name` always `probe`: the name of the service's type in the catalogue, one service of a type per host, `approval-formats.md` section 3) and `claim` (the model's own words,
passed through).

## 2. One endpoint, no state

- `POST /mcp`, MCP streamable HTTP, JSON-RPC 2.0 in the body. `GET /mcp` is
  answered `405`: the service never starts a message of its own.
- **No MCP session id.** The service keeps nothing between requests: every
  tool call carries everything that decides it, and the limits on how much an
  agent asks are pledge's (`approvals.md`, section 7). `initialize` answers
  `serverInfo` (`probe`, its version), `capabilities.tools` with
  `listChanged: false`, and `instructions` (section 5).
- A request that carries an `Origin` header is refused with `403`. Agents are
  not browsers, and a browser cannot sign; this closes DNS rebinding without
  relying on it.
- `tools/list` and `initialize` need no call: they reveal the table, which
  every account on the host could learn anyway (`open`). `tools/call` is the
  only method that acts, and it needs the two headers below.

## 3. The two headers

| Header | Value |
|---|---|
| `Procession-Call` | the call's bytes, base64 (standard alphabet, padded) |
| `Procession-Call-Signature` | the call's signature, **as armoured text, base64-encoded again** |

The armoured SSHSIG has line breaks, which a header cannot carry. Since
`approval-formats.md` section 1 (a signature inside another document is the
base64 of its armoured bytes), the header value **is** the value of the
request's `call_sig`, and `Procession-Call` is the request's `call`: the
service copies both into the request without decoding or re-encoding them
(it decodes a copy to read the call). The signer's keys must be Ed25519 or
ECDSA P-256 (`approval-formats.md` section 3.1); `p-act` refuses others.

Rules at the service, all before the call is looked at:

- each header exactly once; missing, doubled or not base64: `400` with a
  JSON-RPC error (`-32600`), because that is a bug in the signer, not a
  decision about an action;
- sizes: the call at most 16 KiB decoded (the format's limit), the signature
  at most 4 KiB decoded, the body at most 64 KiB, so the headers may reach
  about 28 KiB. **This is more than many HTTP servers and proxies accept by
  default** (8 KiB is common). Calls of this service are small (at most 64
  parameters of at most 512 bytes), so I propose the signer keeps them below
  6 KiB, and `probe serve` sets its own header limit to 32 KiB; see "Open".

## 4. The tool call must say what the call says

The body of `tools/call` repeats the action and parameters, because that is
what an MCP client and its model understand. Repeating is a risk: a signer bug
or an attacker could pair a signed call for one action with a body asking for
another. So **the service acts only on the signed call, and refuses a body
that differs from it**:

- tool `name` = the call's `action` with each space replaced by `_`
  (`rt procs` is `rt_procs`). Nouns and verbs are `[a-z][a-z0-9-]*`
  (`rules.rs`) and never contain `_`, so the mapping is unambiguous both ways;
- `arguments.params` = the call's `params`, element by element, byte for byte;
- `arguments.claim` = the call's `claim`, or both absent;
- `arguments.wait_seconds` is the signer's, not signed, and not acted on (the
  deadline is the call's).

Any difference: outcome `refused`, reason `mismatch`, nobody asked.

## 5. The tool list comes from the table

`tools/list` is generated from the verb table (`src/table.rs`), the one place
that knows the verbs; nothing is written twice.

- A tool for every row that is `ready` in this build and not hidden by the
  service's configuration. Rows that are `unavailable` (their tool is not
  built) are **not listed**: an agent cannot use them, and `sys kit` names
  them for a person. `run command` is listed only when stage 4 is switched on.
  Test verbs appear in a test build only.
- `name`: `<noun>_<verb>`. `title`: `<noun> <verb>`.
- `description`: the row's summary, then one sentence with the rating in
  words, e.g. "Rated: exposure internal, damage none, disruption none (worst
  case). Your person may be asked; the call waits until its deadline." The
  words come from the same function the dialog uses (`table::exposure` etc.),
  so an agent and a person read the same.
- `inputSchema`: `params` (array of strings, `maxItems` 64, each `maxLength`
  512 and `pattern` the argument class of `rules.rs`; `maxItems: 0` for a verb
  without arguments), `claim` (string, `maxLength` 200), `wait_seconds`
  (integer 1 to 600); `additionalProperties: false`.
- `annotations`: `readOnlyHint` when damage is `none`, `destructiveHint` when
  damage is `lasting`, `openWorldHint: false`. Hints are advice for clients;
  nothing relies on them. The exact rating is in `_meta.procession.rating`.
- A test checks that every ready row has exactly one tool, names are unique and
  at most 64 characters, and the schema's pattern accepts what
  `rules::check_argument` accepts and nothing else.

## 6. What an agent sees

A tool call blocks until it is decided, up to its deadline. The result is a
normal MCP tool result. What the agent can act on is the **first text
content**, always one JSON object on one line:

```json
{"type":"outcome","outcome":"declined","id":"3f2b6c1e-8a57-4d0e-9b1a-5c2e7d9f0a11","reason":"person-declined"}
```

`isError` is `true` for everything except a verb that ran and exited 0. The
answer of a verb, one JSON object per line as the dispatcher writes it, follows
as further text content (or none).

| `outcome` | Meaning | `reason` (a fixed list) | What the agent should do |
|---|---|---|---|
| `done` | the verb ran | `rc` is in the object; `isError` follows `rc != 0` | use the answer |
| `declined` | the person saw the request and said no | `person-declined` | not repeat it unless the person asks. Said so in the text |
| `refused` | someone said no without asking the person: the service, the broker, pledge | see below | change the call, or stop; do not repeat unchanged |
| `expired` | the deadline passed without an approval | `no-approval` | may ask again as a new call (new identifier), and should say so to the person first |
| `unavailable` | the service could not reach pledge or the broker, so nothing was asked; at once, not at the deadline | `no-route` | the same as `expired`: nothing was done |

Reasons for `refused`: `review-service-sock.md`, section 3, replaces the
list that stood here. The service passes on, unchanged, the `reason` pledge
(stage 2: the broker) sent when it is in the closed list below, and uses these
names for what it decides itself, so an agent meets one vocabulary. A `reason`
outside the list becomes `unknown`; the service never copies a string it
received into what an agent reads. The list:

- from the service: `invalid-call` (names another host or service, unknown
  verb, arguments not accepted, a string that cannot be shown), `mismatch`,
  `approval-invalid` (what came back did not verify, or was the automatic key
  for a request rated at the top; nothing ran), `call-used`;
- from pledge (`service-sock.md` section 4): `malformed`, `unknown-delegation`,
  `delegation-ended`, `delegation-withdrawn`, `deadline-past`,
  `deadline-too-far`, `call-used`, `service-mismatch` (a fault of this
  service's installation, its key or certificate: an operator must act, and
  the service logs it), `not-showable`, `limit`, `muted`, `ceiling`;
- from the broker (stage 2, its own document): `not-permitted` (the person may
  not, or the person's groups are not among the binding's `groups`) and what
  that document adds.

Pledge's `refused`/`unavailable` (it could not ask or record) and a service
that cannot reach pledge are both the outcome `unavailable`, with the reasons
`pledge-unavailable` and `no-route`. The deadline checks of step 3 in section 8
use `deadline-past` and `deadline-too-far`, not `invalid-call`.

(The earlier, coarser list, kept for the thinking behind it: `invalid-call` (names another
host or service, ended, unknown verb, arguments not accepted),
`mismatch`, `over-ceiling` (rating above what the delegation allows),
`not-permitted` (the site's rules), `delegation-ended`, `muted` (declined too
often), `limit` (too many waiting), `used` (the identifier was used before),
`approval-invalid` (what came back did not verify; nothing ran).) The detail
stays in the service's audit line and in pledge's record. An agent that is told
`not-permitted` can stop wasting calls; it does not learn the site's rules.
This list needs the answer format of the next documents (service to broker,
pledge to broker) to carry such a code. That is a request, below.

`instructions` (in `initialize`) says in plain words what the text above says:
a call may need your person's approval and waits for it until its deadline;
"declined" and "refused" are decisions, do not retry them unchanged;
"expired" and "unavailable" mean nothing happened.

## 7. Waiting, cancelling, dropping

- The service holds the request open until the call is decided or its deadline
  passes. If the client sent a `progressToken`, the response is an SSE stream
  with `notifications/progress` at the steps that matter ("handed to your
  person's machine", "approved, running"; pledge sends nothing between ask and
  answer, so the service cannot say that a dialog is on screen), and a comment line every 15 seconds so that nothing in between
  closes an idle connection. Without a token the response is plain JSON, sent
  once.
- **A cancelled or dropped call is not run.** `notifications/cancelled`, or the
  connection closing, before the verb started: the service stops waiting,
  records the identifier as used, and runs nothing, even if an approval
  arrives later. Nobody is left to read the answer, and an approval was for a
  call someone was waiting on. (The request is still with pledge until its
  deadline; asking pledge to close the dialog needs a cancel message in the
  connection to the broker. Request below.)
- A connection lost **after** the verb started: the verb finishes, the answer is
  lost. The identifier is used, so the agent must make a new call, which asks
  again. Accepted: a verb is not made repeatable to save a dialog.
- At most 16 calls wait in the service at once in stage 1: the protocol's
  limit of open asks on one connection (`service-sock.md` section 4), which the
  service keeps itself rather than provoke `too-many-asks`. It is a bound on
  the connection, not a rule about who may what; beyond that, `503`
  with `Retry-After`, as a transport decision, no outcome.

## 8. What the service does with a tool call, in order

This is `SPEC.md`, "What the service does with a call", with the HTTP in
front:

1. headers present, sizes, base64 (`400` otherwise);
2. parse the call (the p-act crate): `v`, `type`, namespaces of what is
   checked later, size, strings;
3. the call names this host and this service; its deadline is neither past nor
   more than 10 minutes away (60 seconds of clock skew allowed);
4. the action is a ready row, the parameters are accepted by its row
   (`rules.rs` and the row's own parameter rules, see `rating-rule.md`);
5. body equals call (section 4);
6. rating, request, wait, the checks before running, the dispatcher: as in
   `SPEC.md` steps 2 to 5.

**The service does not verify the agent's certificate** (it cannot,
`approvals.md` section 5; pledge and the broker do). So a stranger can make the
service do steps 1 to 5 up to the signing of a request, which pledge or the
broker then refuse. This is the reason for the bound on waiting calls, and
for the service signing nothing until step 5 has passed.

## What I need

- **p-act:** a function that takes the two header values and returns a call
  (parsed, with its bytes and signature kept untouched), refusing what section
  3 of the formats refuses. The signer's side of the same function.
- **An owner for the signer** (the agent-side piece of section 1). It needs the
  agent's key and certificate, which pledge gives the sandbox. Probably
  pledge's crate or p-act, but not p-robe.
- **From the connections documents:** the answer to a request carries a code
  from the list of section 6; and a way to say "this call was cancelled" to
  pledge.

## Open, for the designer

1. **Header size.** Calls in headers is decided; their size is not. If 32 KiB
   of header is not acceptable between sandbox and service, the call has to
   be shorter (fewer parameters), or ride in the body with only the signature
   in a header, which changes the decision. I propose: keep it in headers
   and set the limits above.
2. **Confidentiality of the answer.** An answer can be `secret`. Stage 1 runs
   the service on loopback or a socket the sandbox reaches on the same
   machine; across hosts the connection needs TLS, and nothing here says
   whose certificate. The signed call protects what is asked, not what comes
   back.
3. **`wait_seconds` not signed.** It only shapes the deadline the signer puts
   in the call; the call's own `deadline` is what counts. Fine, but the model
   chooses how long a person is made to wait, up to 10 minutes. Is that wanted,
   or should the signer decide alone?
4. **Reason codes** to an agent (section 6): how much should an agent learn
   about why it was refused?
