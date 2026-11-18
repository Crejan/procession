# `pact`, the agent's signer - a proposal (second version)

Status: a proposal for the orchestrator, the designer and the owner. No code.
Revised after the p-robe agent's review (`crates/p-robe/proposals/review-pact.md`)
and against the service's side as updated (`crates/p-robe/proposals/agent-to-service.md`),
`doc/approvals.md` (section 10 decides `pact`), `doc/approval-formats.md` and
`doc/approval-connections.md`. Terms as approvals.md section 1: "agent" is the
AI agent; the other thing is the "SSH agent".

**Third version (2026-11-11), after the designer's decisions**, which this
document now follows:

- **a.** Signing is in process, with `ring`, with three limits: an agent's key
  is Ed25519, always (`pact` refuses any other; the library's
  `verify_call`, `signature_agent` and the others refuse an agent
  certificate that certifies another type); the in-process writer exists only
  in `pact`, behind its feature, and writes only `call-v1@procession`
  (everything else in `p-act` keeps signing through `ssh-keygen`); and its
  specification is a test: for the same key, certificate and message its
  armoured output is byte for byte what `ssh-keygen -Y sign` writes, and
  `ssh-keygen -Y verify` accepts it.
- **b.** Separation of key and model is a SHOULD (approvals.md R2). `pact`
  does its own part regardless and logs a warning when a client connects as
  `pact`'s own user. The seven conditions below are what "apart" means, a
  description of a good sandbox and not something `pact` checks.
- **c.** `no-answer` is an outcome of its own, `unknown`: the call was sent
  and whether it ran is not known.
- **d.** The bundle is option B.
- **e.** Progress is `pact`'s own, never relayed: every 15 seconds while a call
  waits, one fixed text.

Still with the owner: the HTTP client (section "Not decided"). This version of
the code builds everything that does not depend on it: see "What exists".

## 0. What changed from the first version

The review made nine points. For each, whether this version adopts it:

| Review | Point | Here |
|---|---|---|
| 1 | `_meta` keys | **Adopted**, decided: flat `procession/call` and `procession/call_sig`, each base64 (section 6) |
| 2 | `params` always present, `[]` when empty; service sees the unprefixed name | **Adopted** (section 6) |
| 3 | read timeout "deadline plus 10 s" is wrong for a running verb | **Adopted**: `progressToken` on every call, an idle timeout of 45 s, no deadline-based timeout (section 7). One dependency on the service, section 7 |
| 3 | a floor on the wait that is signed | **Adopted**: 10 s or the setting if smaller; configurable for tests (sections 2 and 6) |
| 4 | body limit must hold a legal answer once wrapped in JSON-RPC | **Adopted**: 4 MiB for the response message, 1 MiB of text passed to the model (section 7) |
| 5.1 | one service: no prefix; several: prefix; collisions or too long refuse to start | **Adopted** (section 5) |
| 5.1 | a tool whose description breaks the rule is dropped; descriptions are one line, at most 600 characters, rating first | **Adopted**; `pact` never cuts a description (section 5) |
| 5.2 | take only `maxItems`, `maxLength`, `pattern` from the service's schema | **Changed**, as decided: the service's schema passes through unless it breaks a stated rule; section 5 says what `pact` adds and why |
| 6 | outcome words: `unknown` becomes `refused`/`not-allowed`; no `invalid-call` of its own; no `no-route`; `rc` in `done`; `reason` only with `refused`; JSON-RPC errors are `unavailable` | **Adopted** (section 8) |
| 6 | `503` with `Retry-After` is `refused`/`try-later`, without it `unavailable` | **Adopted** (section 8) |
| 6 | `no-answer` is `pact`'s alone and the designer must add it | **Decided**: an outcome of its own, `unknown` (section 8) |
| 6 | the same call arriving twice is the service's `invalid`; a lost answer is repaired only by a new call | **Adopted** (section 6.3) |
| 7 | HTTP details: `Accept`, no `Origin`, `MCP-Protocol-Version`, `Content-Type`; no `initialize` needed | **Adopted** (section 7) |
| 7 | limit of 16 | **Adopted**; compatible with the service's 16 per service |
| 7 | `http+unix` not needed | **Adopted**: services are `http`/`https` URLs only (section 2) |
| 7 | progress not relayed | **Adopted, and decided further**: never relayed from a service; `pact` sends its own, every 15 seconds, one fixed text (section 7) |
| 7 | instructions say what `unknown` means | **Adopted** (section 4) |
| 8 | which document changes what | this document changes in all the places above |
| 9 | what the end-to-end test needs | **Adopted**: section 10 |

## 1. What it is, and where it runs

`pact` is a small binary of the crate `p-act`, built only with the cargo
feature `pact` (`[[bin]] required-features`), so that the library that
p-ledge, p-age and p-robe use gains no dependency. It runs in the sandbox, as
the one program that:

- holds the agent's key and certificate,
- turns each of the model's tool calls into a call, signs it, and sends it,
- is the only thing in the sandbox that talks to services.

The model sees tools, arguments and answers. It never sees the key, the
identifier, the deadline logic or the `_meta`.

Three commands from one binary:

| Command | Does | Holds the key |
|---|---|---|
| `pact serve` | started by the person's SSH connection that starts the sandbox; reads one bundle from standard input (section 2), closes it, and stays. `--socket-mode` sets the socket's mode (default `0600`). Listens on a Unix socket. Speaks MCP on that socket, and HTTP to the services | yes, in memory |
| `pact stdio` | started by the model's MCP client as its "server"; copies bytes between its standard input/output and the socket. Reads no file and holds nothing | no |
| `pact call <tool> '<arguments json>'` | one call, no server and no socket: reads the bundle from standard input, composes, signs, sends and prints the normalised tool result as one JSON object on standard output. The same code path as `tools/call` (section 6). For a person trying a service by hand, and for tests (section 10). `--min-wait SECONDS` (a test option, here and in `serve`) sets the floor. `pact tools` likewise prints the tool list | for its one run |

Why two processes for the model: the model's MCP client starts `pact stdio`
itself and may start it many times; the key must not be on a command line, in
an environment variable or in a file the client's configuration names. Why a
socket and not a loopback port: anything else in the sandbox's network
namespace could reach a port; a socket has a mode. (A client that only speaks
HTTP can be given a loopback port as an option later.)

How far the model is kept from the key depends on the sandbox, not on `pact`
(approvals.md R2: a SHOULD). What "apart" means is in "What 'apart' means"
below.

## 2. What arrives on standard input (decided: option B)

**The exact bytes**, which `pact` reads and pledge writes, and which `pact`
refuses to read in any other form (`p_act::pact::bundle`):

```
<configuration: one JSON object, no line break inside>\n
-----BEGIN OPENSSH PRIVATE KEY-----\n
<the key's base64, in lines>\n
-----END OPENSSH PRIVATE KEY-----\n
<certificate: ssh-ed25519-cert-v01@openssh.com <base64> [comment]>\n
```

- Line ends are `\n` only; a `\r` anywhere is refused.
- The configuration line is JSON, with its string escapes (a PEM root has `\n`
  escaped inside the string, no raw line break). `pact` reads members in any
  order; what pledge writes (`Bundle::write`) is in the order `v`, `services`,
  `deadline_seconds`, `tls_root`.
- The key block follows the line directly, with nothing between. It is the file
  `ssh-keygen` writes: the begin line, the base64 in lines, the end line with
  its `\n`. `ssh-keygen` wraps at 70 columns; `pact` reads any width, but no
  empty line.
- The certificate line follows the end line directly: one line, the type, one
  space, the base64, optionally a space and a comment, **then exactly one `\n`,
  which is required**. Nothing follows it: not a blank line, not a second
  line, not a space.
- **64 KiB counts over everything read from standard input**, all three parts
  together: more is refused as too large, whatever it holds. (`pact` reads 64 KiB
  and one byte, so it never reads without end.)
- Each part has its own error: no configuration line, a configuration that
  breaks a rule, a key block that is missing or malformed or encrypted or of
  another type (named), a certificate line that is missing or malformed or not
  for the key or expired or that breaks section 3.1, a missing final line feed,
  trailing data.

In words, the three parts:

1. **one line**: the configuration as one JSON object with `v`;
2. **the key**, an unmodified unencrypted OpenSSH private key block, which a
   person can produce with `cat`;
3. **the certificate**, one `-cert.pub` line (which is what `ssh-keygen -s`
   writes, with its `\n`).

```json
{"v":1,"services":[{"host":"a.example","name":"probe","url":"http://127.0.0.1:8443/mcp"}],"deadline_seconds":120,"tls_root":"-----BEGIN CERTIFICATE-----\n..."}
```

- `services`: the **only** services `pact` will talk to (1 to 16). `host` and
  `name` are what goes in `service` of each call; `url` is where to send it:
  `https`, or `http` on loopback (`localhost`, `127.x.x.x`, `::1`) only; no
  credentials, no fragment, no control or non-ASCII character. Nothing in
  this list comes from the model.
- `deadline_seconds`: the setting, 1 to 600, default 120.
- `tls_root`: a PEM certificate; required if any service is `https`.
- **The floor for the wait is not in the bundle** (`min_wait_seconds` is an
  unknown member and refused): it is the option `--min-wait SECONDS` of the
  command line (default 10, or the setting if smaller), for tests.
- Unknown members, a `v` that is not 1, a bundle over 64 KiB, a duplicate
  service: refused. pledge writes the bundle when the person starts the agent
  (approvals.md flow A), in one buffer, with `Bundle::write(&Config, &KeyBlock,
  certificate, now)`: the key is a `KeyBlock` that prints nothing and is zeroed
  when it goes, and what is written is read back with the parser before it is
  returned, so pledge never hands out a bundle `pact` would refuse. The shared
  numbers (the 600 seconds, the 64 KiB) are `p_act::limits`.
- The key must be Ed25519, unencrypted, and its certificate must be its own
  (fingerprint compared), a user certificate, valid now, and keep to formats
  section 3.1: one principal, no critical option, no extension but a
  well-formed `groups@procession`. Each failure has its own error, and no error
  holds any of the key.

`pact serve` refuses to start on any problem, with one line on standard
error that never contains key material.

## 3. Signing (decided: in process)

The signature is an SSHSIG over the call, namespace `call-v1@procession`, by
the agent's Ed25519 key and its certificate, written by `pact` itself with
`ring`: the `SSHSIG` blob (the certificate as public key, namespace, empty
reserved, `sha512`, the signature over the signed-data structure), armoured at
70 columns. Three limits, decided:

1. **The agent's key is Ed25519, always.** `pact` refuses any other type, naming
   it; the library's `verify_call`, `signature_agent`, `signature_person` and
   `request_person` refuse an agent certificate that certifies another type, with
   `SignError::AgentKeyNotEd25519`.
2. **The writer exists only in `pact`**, behind the feature, and writes only
   `call-v1@procession`: its public function takes a `Call`, not bytes.
   Everything else in `p-act` signs through `ssh-keygen`.
3. **The test is equality, and it is the writer's specification.** For the same
   key, certificate and message, `pact`'s armoured output is byte for byte what
   `ssh-keygen -Y sign` writes (Ed25519 is deterministic), over every namespace
   of the system and others, with and without a certificate, for messages from 0
   to 200,000 bytes; and `ssh-keygen -Y verify` accepts it, and refuses it for
   another namespace, changed bytes and an expired certificate.

The key lives in `pact`'s memory only: no key file, nothing in the environment
or the arguments. The process is made not dumpable and without core files; the
buffers that held the bundle are wiped on a best-effort basis.

## 4. How the model's client talks to `pact`

`pact stdio` is an MCP server on stdio, which every MCP client can start.
Behind it `pact serve` is the MCP server proper. It implements `initialize`
(negotiating the protocol revision it knows), `ping`, `tools/list`,
`tools/call` and `notifications/cancelled`. It offers no resources, prompts,
sampling or roots, and answers any other method `method not found`. Its
`instructions` say what the service's say: a call may wait for the person's
approval until its deadline; `declined` and `refused` are decisions, do not
repeat them unchanged; `expired` and `unavailable` mean nothing happened (and
for `unavailable` trying again is safe); **`failed`: the call was approved and
the action was started, and it did not complete: no result, something may have
happened on the host, and an action that changes something must not be repeated
blindly, find out what happened first; `unknown`: the call was sent and whether
it ran is not known; before repeating anything that changes something, find out
by a query.**

## 5. Which services exist, and the tool list

Services are exactly those of the bundle. At the first `tools/list`, and then
every 5 minutes (never more often than every 30 seconds), `pact` asks each
service `tools/list`, which needs no call (agent-to-service.md section 2), and
builds its own list.

- **Names** (decided between the two parts). The service's tool is
  `<noun>_<verb>`. With **one** service in the bundle the model sees it as it
  is. With **several**, `<name>__<host>__<noun>_<verb>`, the host with `.`
  replaced by `-`, so that two hosts offering `probe` cannot collide. A name
  must be `[a-zA-Z0-9_-]{1,64}`. `pact serve` refuses to start if two services
  of the bundle map to one prefix. A tool of a service whose prefixed name
  would exceed 64 characters, or that is not an action of the formats grammar
  when `_` is read as a space, or whose name is not unique, is **dropped** with
  a line on standard error naming the tool and the reason. The service
  receives the unprefixed name; the prefix exists only between the model and
  `pact`.
- **Text.** `title` and `description` are the service's, which writes them as
  one line of at most 600 characters, the rating first
  (agent-to-service.md section 5). `pact` never cuts them. A tool whose text
  is longer, has a control or bidirectional character (formats section 2) or a
  line break is dropped, not repaired. This is text from a service into a
  model's context, which is a prompt injection channel; services are trusted
  to do what they say (approvals.md section 4), so `pact` bounds it and does
  not judge it. `annotations` pass through. `_meta` of a tool, which carries
  the exact rating for clients, is dropped.
- **The schema is the service's** (decided). `pact` passes the service's
  `inputSchema` through, so the model keeps `maxItems: 0` for a verb without
  arguments, the argument pattern, and the lengths. `pact` checks it first,
  and the check is the whole of what `pact` adds:
  1. It must be of the shape agent-to-service.md section 5 gives: an object
     with `params` (array of strings), `claim` (string) and `wait_seconds`
     (integer), `additionalProperties: false`. Keywords other than `type`,
     `maxItems`, `maxLength`, `minimum`, `maximum`, `pattern` and
     `description` (one line, under the same rule as above) are removed;
     `$ref`, `default`, `examples` and any `description` that breaks the rule
     make the tool dropped. A schema is data for the model, not something
     `pact` follows.
  2. A bound is **never widened**: `params.maxItems` is at most 64,
     `params.items.maxLength` at most 512, `claim.maxLength` at most 200;
     a larger number is replaced by the format's, because a call larger than the
     format's is not a call.
  3. `wait_seconds` is **`pact`'s own**: `minimum` the floor, `maximum` the
     setting. The service cannot know the setting, and the model must not be
     told it may wait longer than `pact` will let it (it may ask for any
     shorter wait down to the floor, never a longer one; a longer one is
     clamped, not an error).
  4. `pattern` is a printable-ASCII string of at most 512 characters, passed on
     as data. **`pact` does not evaluate it**: that would need a regular
     expression engine for text a service chose, and the service enforces the
     class anyway. `pact` does enforce the numeric bounds before it signs
     (`maxItems`, `maxLength`), because a refusal there costs nothing and a
     refusal by the service after signing is a spent call.

  What a schema of `pact`'s own would add beyond this is only (2) and (3), and
  those are done on the service's schema in place.
- `listChanged` is `false`. A service that cannot be reached at refresh time
  keeps its last list; one never reached offers no tools and `pact` says so on
  standard error.

## 6. Composing the call from a tool call

For `tools/call` with `name` and `arguments`:

1. Unknown name, or `arguments` with a member other than `params`, `claim` and
   `wait_seconds`, or a member of the wrong type, or a violation of a bound of
   section 5: an MCP error result (`isError`), nothing is signed. This is the
   model's mistake and it is said plainly ("params must be an array of strings
   of at most 3"). It is not an outcome.
2. `service` is the table's `{host, name}`; `action` is the table's. `params`
   and `claim` are the model's as given (no trimming, no re-encoding);
   `Call::compose` applies the formats' limits and string rule, and a refusal
   is the same MCP error with the `ParseError` text (which says which member
   and why, and holds nothing secret).
3. `id`: a fresh version 4 UUID from the operating system's random source
   (`ring::rand`, no new dependency), per tool call, never reused, and **never
   sent twice**: a transport failure is never answered by sending the same call
   again. The model may make a new tool call, which is a new call with a new
   identifier. A lost answer cannot be repaired by repeating; the service
   answers a repeated call `invalid` (`call-used` in its audit line), which is
   true: the call is spent.
4. `deadline`: now plus `max(floor, min(wait_seconds, setting))`; with no
   `wait_seconds`, now plus the setting. The model can shorten the wait down to
   the floor and never lengthen it. The floor exists because the service
   applies no tolerance toward a deadline already past (approvals.md R7): a
   sandbox clock 60 seconds behind and a wait of 30 would put the deadline in
   the service's past. If a service answers `deadline-past` or
   `deadline-too-far` for a call whose deadline came from the setting, that is
   a clock fault, and `pact` says so once on standard error.
5. Sign (`call-v1@procession`), then send `tools/call` to the service's URL
   (section 7):
   - `name`: the action with spaces replaced by `_`;
   - `arguments`: `{"params": [...], "claim": "..."}` exactly as signed,
     `params` always present (`[]` for none), `claim` absent if the call has
     none; `wait_seconds` is dropped, it was `pact`'s;
   - `_meta`: `"procession/call"` (the call's bytes, base64),
     `"procession/call_sig"` (the armoured signature's bytes, base64: the same
     values as the request's `call` and `call_sig`, formats section 4) and
     `"progressToken"` (a fresh value, see section 7). **Exactly these two
     `procession/` keys and no third.**

`arguments` must equal the signed call (approvals.md section 10); `pact`
builds both from the same `CallContent`, so it cannot differ.

## 7. Talking to a service

HTTP/1.1, one request per connection (`Connection: close`), a thread per
waiting call (at most 16 at once; more get `unavailable` at once). Blocking
sockets, no async runtime. Headers on every POST: `Content-Type:
application/json`, `Accept: application/json, text/event-stream`,
`MCP-Protocol-Version: 2025-06-18`, `Host` as configured; **no `Origin`**.
`pact` does not call `initialize` (the service takes `tools/list` and
`tools/call` without it and without a session id).

- Only the configured URLs. No redirects followed (a redirect is
  `unavailable`). No proxy variables read. No credentials in a URL. `https`
  verifies the service's certificate against `tls_root` and the configured
  host name, nothing else.
- **A running verb is not a lost answer.** The deadline bounds the start of an
  action, not its run (approvals.md R7). So `pact` sends a `progressToken` with
  every call, the service answers with an SSE stream and a comment line every
  15 seconds (agent-to-service.md section 7), and `pact` applies an **idle
  timeout of 45 seconds**: no byte for 45 seconds is a dead connection. There
  is no timeout counted from the deadline, and none counted from the start of
  the call: a verb is waited for as long as the service keeps the stream alive,
  which is as long as the service's own bound on a run (the table's per-verb
  run limit that the service enforces). Connect: 10 seconds.
  **This needs the service to send the SSE response head at once, when it
  accepts the call, not at its first notification**: before the head `pact`
  has only the idle timeout to go by, and an approval can take the whole
  deadline, up to 10 minutes. I ask the p-robe agent to confirm this.
- Responses: `application/json` (read once; it is the final answer) or
  `text/event-stream` (comments and `notifications/progress` ignored; the
  JSON-RPC response whose `id` is the request's is the answer). **The final
  message may be up to 4 MiB**: a verb's answer is capped at 1 MiB of lines,
  and wrapped in JSON-RPC every `"` is doubled, so a legal answer can reach
  about 2 MiB; 4 MiB leaves room and bounds `pact`. Notifications and comments
  together at most 64 KiB. Content-Length and chunked encodings. A larger
  message is `unknown` (the verb may have run). What `pact`
  hands on to the model stays at 1 MiB of text content, as the service caps it;
  a final message that has more is a protocol violation and is treated the same.
- **Progress is `pact`'s own, never a service's** (decided). While a call
  waits, `pact` sends the model's client a `notifications/progress` every 15
  seconds, with the client's own `progressToken` (if the client sent one), an
  increasing `progress`, and the one text "waiting for an answer". Nothing a
  service sends is relayed. This keeps a client that resets its request
  timeout on progress waiting for a person's answer.

## 8. What the model gets back

The service's tool result, normalised. Its first text content is one JSON
object `{"type":"outcome","outcome":...,"id":...,"reason":...}`
(agent-to-service.md section 6): `reason` only with `refused`, `rc` also in a
`done`. `pact`:

- parses it, and passes it on only if `outcome` is one of `done`, `declined`,
  `expired`, `refused`, `unavailable` or `failed` and, for `refused`, `reason` is one of
  `not-allowed`, `invalid`, `try-later`. **A `refused` with another reason
  becomes `refused`/`not-allowed`** ("do not repeat" is the safe reading). **A
  response that is not an outcome for this call at all (no outcome line, another
  identifier, an outcome outside the list, `done` without `rc`, an answer over
  the limit) is `unknown`**, because the call was sent and may have run. It never
  passes on a string it received and did not parse into the closed list: `done`,
  `declined`, `expired`, `refused` with its class, `unavailable`, `failed`,
  `unknown`;
- **`failed`** (decided by the designer, `approvals.md` section 10; only a
  service says it): the call was approved and the action was started, and it
  did not complete. There is no result; something may have happened on the
  host; the cause is in the service's log and the host's audit lines under the
  call's identifier. It is not `unavailable` (nothing was done) and not
  `unknown` (the call was sent and whether it ran is not known: only `pact`
  makes that one). The line is `{"type":"outcome","outcome":"failed","id":...}`,
  and the text content after it is fixed (`FAILED_TEXT`): the call did not
  complete, there is no result, something may have happened, **do not repeat it
  blindly if it changes anything, find out what happened first, by a query**,
  and the cause is under the call's identifier in the logs. Whatever the service
  adds to its outcome (a reason, a code, a detail, further texts) is not passed
  on. `isError` is true. Until the service's wire form is merged, `pact` accepts
  the outcome word `failed` with no other member;
- passes the answer of a verb (`done`) on as the further text contents,
  unchanged, up to 1 MiB: that is the data the model asked for;
- makes its own outcomes for what happens on its side, with the same shape:
  - `unavailable` (no reason): nothing was sent, or the connection was refused,
    the TLS check failed, the service answered `5xx` without `Retry-After`, a
    redirect came, or a JSON-RPC error (`-32600`, `-32602`: a bug of the
    signer, since `pact` builds the call itself; the code goes to standard
    error). Nothing was done;
  - `refused`/`try-later`: the service answered `503` with `Retry-After`, or
    more than 16 calls were waiting in `pact`;
  - **`unknown`** (decided; only `pact` makes it): the call was sent and no
    answer came (the connection was lost, or the idle timeout, or an answer over
    the limits). **A verb may have run** (agent-to-service.md section 7). The
    text content after the outcome line tells the model to find out by a query
    before it repeats anything that changes something;
  - a model's mistake is an MCP error (section 6), never an outcome, and
    `invalid` comes only from a service;
- on `notifications/cancelled` from the model, closes the connection to the
  service (which is the service's cancel) and answers nothing further.

No HTTP status, header, error body, TLS message or system error text reaches
the model, only the words above. Detail goes to standard error (the sandbox's
log), without key material, with the call's `id` and hash and not its
parameters.

## 9. What `pact` must never do

- Show the key: not in output, errors, logs, arguments, the environment,
  `/proc` listings, crash messages (`panic = "abort"` with a fixed message for
  the `pact` binary), or any tool. The key is held in memory only, the bundle
  read once and its buffer wiped.
- Sign anything but a call that it composed itself from a tool call. There is
  no tool, method or socket message that takes bytes to sign, and the namespace
  is fixed in code, so it cannot make an approval or a clearance signature by
  being asked cleverly. The signing function takes a `Call`, not bytes.
- Talk to anything but the configured services: no URL from the model, no
  redirect, no second host, no DNS name but the configured one, no proxy chosen
  by the environment.
- Send a call twice, lengthen a deadline, or reuse an identifier.
- Write to disk, other than the socket's directory entry, or read any file
  after start (a Unix socket's path is an argument, not a file read). All
  configuration arrives on standard input.
- Trust the answer: it is a model's input, bounded in size, and `pact` does
  not act on it.

## 10. A stage-1 end-to-end test

What the p-robe agent asks for (review section 9), on one machine over
loopback, with a real `probe serve` (test verbs), a real `pact`, and a fake
pledge.

1. **A bundle, by recipe and by function.** The recipe, from a scratch
   directory (the delegation key stands for pledge's, the person is `alice`):

   ```
   ssh-keygen -q -t ed25519 -N '' -C '' -f delegation
   ssh-keygen -q -t ed25519 -N '' -C '' -f agent
   ssh-keygen -q -s delegation -I agent -n alice -V +8h -O clear agent.pub
   echo '{"v":1,"deadline_seconds":5,"services":[{"host":"localhost","name":"probe","url":"http://127.0.0.1:8443/mcp"}]}' > bundle
   cat agent agent-cert.pub >> bundle
   ```

   (the configuration line, the key, the certificate line: section 2). The
   test helper of `p-act` builds the same thing from real keys, so that tests of
   p-robe and p-ledge do not each write it.
2. **Driving `pact` without an MCP client:** `pact call <tool> '<json>' <
   bundle.json` and `pact tools < bundle.json`, as in section 1; the result is
   the normalised tool result on one line, exit status 0 whenever `pact` itself
   worked (the outcome is in the JSON).
3. **The identifier and the call's hash on standard error** of every call, so
   that a test can find it in the service's audit line and in the fake
   pledge's log.
4. **A short `deadline_seconds` in the bundle and the floor as the option
   `--min-wait`** (above: 5 and 1), so that a test of `expired` takes 5 seconds and not 120.
5. **A fake pledge** from `p-act`. Everything it needs exists now:
   `exchange` (`LineReader`, `Message`, `write_message`), `verify_request` and
   `verify_call_agent` for the checks, `sign_approval` with a confirmed and an
   automatic test key, and `ApprovalTrust::PersonKeys` on the service's side.
   What it lacks is only a script: "approve with the automatic key", "approve
   with the confirmed key", "decline", "refuse with this reason", "never
   answer", "answer then drop the connection". I can add that as
   `p_act::testing::FakePledge` (feature `test-support`) if wanted; the p-robe
   agent may equally write it from the public API.
6. **What `pact` tests itself**, with a fake service on loopback (a
   `TcpListener`), without `probe`: each outcome of section 8 including
   `unknown` and an unknown reason; a verb that runs for 60 seconds with
   keep-alive comments, which must not become `unknown`; an answer of 3 MiB
   of JSON; the refusals of section 6 sign nothing (the fake sees no
   connection); a key not matching its certificate, an expired certificate, a
   certificate with a critical option, an RSA key: `pact serve` refuses to
   start and standard error holds no part of the key; a redirect, a wrong host
   name, a service that answers for another id; the call is verified on the
   fake side with `verify_call_agent` and parsed with `Call::parse`, and its
   `arguments` equal the call, `params` is present, `_meta` has exactly two
   `procession/` keys, the deadline is within the setting and above the floor,
   the id is new each time, and nothing is sent twice after a dropped
   connection.

The scenarios of the review (`test echo` unasked, `test peak` asked and
refused with the automatic key, declined, each `refused` reason, `expired`, a
lost connection after the verb started, a replayed call, a body that differs,
cancel, the 17th waiting call, `tools/list` as `pact` presents it, `test read`
through `--within`) are p-robe's tests and use items 1 to 5.

## What "apart" means (decided as a SHOULD)

`pact` does its own part regardless of the sandbox: it lowers the exposure (no key file in the in-process case, nothing in the
model's context, nothing in its environment or arguments, `PR_SET_DUMPABLE` 0,
no core dumps). That is **not** secrecy from a model that can run code as the
same user. What "apart" means, precisely: a description of a good sandbox, not a precondition that `pact` checks: `pact serve` runs as a
**user that no process the model can start runs as**, and:

1. no capability that reads another user's process or files is granted to the
   model's processes (`CAP_SYS_PTRACE`, `CAP_DAC_READ_SEARCH`,
   `CAP_DAC_OVERRIDE`, `CAP_SYS_ADMIN`), and `ptrace` between the users is
   denied (it is, by default, between different users without
   `CAP_SYS_PTRACE`);
2. `/proc/<pid>/mem`, `environ`, `cmdline` and `maps` of `pact serve` are not
   readable by the model's user: with another user and `dumpable` 0 they are
   owned by root; better, a separate PID namespace or `hidepid=2` for `/proc`;
3. the binary `pact`, its configuration (none on disk) and the directory of the
   socket are **not writable** by the model's user, so that it cannot replace
   the program that will hold the key;
4. the socket is reachable by the model's user (it is the interface), with a
   mode that gives exactly that user and `pact`'s the right to connect. What it
   can do through the socket is what a tool call can do and nothing else
   (section 9);
5. the model's user has no way to start a `pact serve` of its own with a bundle
   it chose; the person's SSH connection starts the one that exists;
6. swap, if any, is encrypted or off, and core dumps are off for `pact`'s user;
7. the model's user cannot reach a service except through `pact`. This one is not about the key (an unsigned call is refused anyway), but without it `pact` is not "the only thing" that talks to services, which approvals.md section 10 says it is.

`pact serve` logs a warning when a client connects under `pact`'s own user
(on Linux, from the peer's credentials on the socket). Where the sandbox does
not keep them apart, the key protects against the model's text and against
accident, not against code the model runs; the design holds either way, since
every use of the key still passes the person's machine and is recorded there
(approvals.md R2).


## Not decided

### The HTTP client, for the owner

The hand-written client over `httparse` was proposed in the first version only
because crates.io cannot be reached from this sandbox; that is not a reason to
design around. With network access I would choose **`ureq` 3** (a blocking
client, `default-features = false`, feature `rustls` with the `ring` provider).
From memory, not checked offline: it pulls `rustls`, `rustls-webpki`,
`rustls-pki-types`, `ring`, `webpki-roots` (or a custom root, which `pact`
needs), `http`, `httparse`, `ureq-proto`, `base64`, `log`, `percent-encoding`,
`url` (and its IDNA dependencies), `utf-8`: about thirty to forty crates, most
of which `p-age` and `p-ledge` pull anyway through `rustls` for the broker
connection (connections document, section 8). It gives correct HTTP/1.1
(chunked, trailers, header limits, TLS) that I would otherwise write, test and
keep honest in a program that holds a key. Its costs: its defaults must be
switched off so as not to break section 9 (redirects off, no proxy from the
environment, no `User-Agent` of its own, no `Accept-Encoding: gzip`, no
decompression), and I do not know from memory how its read timeout treats a
stream that stays open: the 45-second idle timeout of section 7 has to be
checked against it, and a hand-written read loop may be needed for the SSE
body anyway. Alternatives: `reqwest` (blocking), larger (`tokio`, `hyper`,
`h2`, `tower`) for a client that makes at most 16 requests at a time;
`minreq`, small and without streaming.

The hand-written option, for comparison: about 400 lines (a request writer, a
response head with `httparse`, chunked decoding, an SSE line reader, limits,
timeouts), exactly the subset section 7 needs and nothing that has to be
switched off, no new dependency but `httparse` and `rustls`, and a client that
only this program uses, which therefore has no audience that reviews it. It
needs its own tests for chunked encoding, SSE, oversized and truncated
responses, a redirect, a wrong host name and a stalled stream. The choice is
between a vetted general client with defaults to disarm, and a small special
one that is ours to get right.


Checked on 2026-11-11 with `cargo generate-lockfile --offline` in a scratch
directory: **`ureq` is not in the local registry** (`no matching package named
`ureq` found`), so the choice cannot be built here either way. `http`,
`httparse`, `rustls` 0.23, `rustls-pki-types`, `rustls-webpki` and `webpki-roots`
are.

## The HTTP client (built on `ureq` 3.5.2)

`p_act::pact::http::HttpTransport`, one `ureq` agent per call. Checked on the fetched crate: the
TLS feature is `rustls` (so `pact-tls = ["pact", "ureq/rustls"]` was right; `ureq` with
`default-features = false` is plain http only); `timeout_per_read` is an idle timeout that
restarts at each read and covers the head and the body, which is the 45 seconds; and
`Agent::shutdown()` closes the connections of an agent in flight, which is how the model's cancel
reaches the service (one agent per call). Disarmed: no redirect (a 3xx is `unavailable`), no proxy
from the environment, no `User-Agent`, no `Accept-Encoding`, `Accept: application/json,
text/event-stream`, `MCP-Protocol-Version`, no `Origin`. A build without `pact-tls` refuses an
`https` bundle at start. An error of `ureq` is mapped to "nothing was sent" only when it can
come from making the connection alone (refused, unreachable, resolve, TLS, bad URL); every
other one after a connection is a lost answer (`unknown`).

## What exists

Behind the feature `pact` (`p_act::pact`, and the binary): the bundle parser with every refusal; the in-process Ed25519 SSHSIG writer and its equality test; composing a call from a tool call; the outcome mapping to the closed list; the progress text and interval; the MCP server on a byte stream, and `serve`, `stdio`, `call` and `tools`; the catalogue with the service's schema checked; and the `Transport` trait with an in-memory implementation. What the HTTP client adds is one `Transport` implementation.

## Dependencies, in short

For the library: unchanged (`serde`, `serde_json`, `base64`, `ring`,
`tempfile`, `thiserror`). For `pact` (feature `pact`): the choice of (e), and
`rustls` with its provider and `rustls-pki-types` for `https`; `libc` for the
one `prctl` call, in the binary only; the command line by hand (three
subcommands); threads and `std` sockets, no async runtime (at most 16 waiting
calls). The in-process signing adds no dependency.
