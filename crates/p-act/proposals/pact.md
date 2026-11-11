# `pact`, the agent's signer - a proposal (second version)

Status: a proposal for the orchestrator, the designer and the owner. No code.
Revised after the p-robe agent's review (`crates/p-robe/proposals/review-pact.md`)
and against the service's side as updated (`crates/p-robe/proposals/agent-to-service.md`),
`doc/approvals.md` (section 10 decides `pact`), `doc/approval-formats.md` and
`doc/approval-connections.md`. Terms as approvals.md section 1: "agent" is the
AI agent; the other thing is the "SSH agent".

What is **decided** (by the designer, or by the orchestrator between the two
parts) is written as such. What goes to the designer or the owner is in the
last part, "Not decided", with both sides and no choice made.

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
| 6 | `no-answer` is `pact`'s alone and the designer must add it | **Agreed that it is needed; the choice is the designer's**, so it is presented in "Not decided" (c). Until then the text below uses it as proposed |
| 6 | the same call arriving twice is the service's `invalid`; a lost answer is repaired only by a new call | **Adopted** (section 6.3) |
| 7 | HTTP details: `Accept`, no `Origin`, `MCP-Protocol-Version`, `Content-Type`; no `initialize` needed | **Adopted** (section 7) |
| 7 | limit of 16 | **Adopted**; compatible with the service's 16 per service |
| 7 | `http+unix` not needed | **Adopted**: services are `http`/`https` URLs only (section 2) |
| 7 | progress not relayed | **Adopted for now**, with a risk written down in section 7 and in "Not decided" (f) |
| 7 | instructions say `no-answer` may have run | **Adopted** (section 4) |
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
| `pact serve` | started by the person's SSH connection that starts the sandbox; reads one bundle from standard input (section 2), closes it, and stays. Listens on a Unix socket. Speaks MCP on that socket, and HTTP to the services | yes, in memory |
| `pact stdio` | started by the model's MCP client as its "server"; copies bytes between its standard input/output and the socket. Reads no file and holds nothing | no |
| `pact call <tool> '<arguments json>'` | one call, no server and no socket: reads the bundle from standard input, composes, signs, sends and prints the normalised tool result as one JSON object on standard output. The same code path as `tools/call` (section 6). For a person trying a service by hand, and for tests (section 10). `pact tools` likewise prints the tool list | for its one run |

Why two processes for the model: the model's MCP client starts `pact stdio`
itself and may start it many times; the key must not be on a command line, in
an environment variable or in a file the client's configuration names. Why a
socket and not a loopback port: anything else in the sandbox's network
namespace could reach a port; a socket has a mode. (A client that only speaks
HTTP can be given a loopback port as an option later.)

How far the model is kept from the key depends on the sandbox, not on `pact`
(approvals.md section 4 trusts the sandbox for "no way out except services"
and not for keeping the key secret). The exact requirement is in "Not
decided" (b).

## 2. What arrives on standard input

One JSON object on one line, then end of input. This is the shape proposed;
whether it is the right one is "Not decided" (d).

```json
{"v":1,"key":"-----BEGIN OPENSSH PRIVATE KEY-----\n...","certificate":"ssh-ed25519-cert-v01@openssh.com AAAA...","services":[{"host":"a.example","name":"probe","url":"http://127.0.0.1:8443/mcp"}],"deadline_seconds":120,"min_wait_seconds":10,"tls_root":"-----BEGIN CERTIFICATE-----\n..."}
```

- `key`: an unencrypted OpenSSH private key, Ed25519 or ECDSA P-256 (another
  type is refused, naming it). `certificate`: its `-cert.pub` line, which must
  pass formats section 3.1 (the `signature_agent` rules), be the key's own,
  and not be expired. Checked at start, so a wrong pair fails at once.
- `services`: the **only** services `pact` will talk to. `host` and `name` are
  what goes in `service` of each call; `url` is where to send it, `http` or
  `https`, no credentials in it. Nothing in this list comes from the model.
  Stage 1 may use `http` on loopback with no `tls_root`; anything else needs
  `https` and a root (the site's own, approvals.md section 5).
- `deadline_seconds`: the setting of section 6, default 120, at most 600.
  `min_wait_seconds`: the floor, default 10 or `deadline_seconds` if smaller;
  settable lower for tests.
- Unknown members, a `v` that is not 1, a bundle over 64 KiB: refused.
- The bundle is put together by pledge when the person starts the agent
  (approvals.md flow A); p-ledge's specification owns its definition.

`pact serve` refuses to start on any problem, with one line on standard
error that never contains key material.

## 3. Signing

The signature is an SSHSIG over the call, namespace `call-v1@procession`,
by the agent's certified key. Two ways to make it, and the choice is the
designer's ("Not decided" (a)). Both produce the same bytes of meaning, and
both are checked in the tests by `ssh-keygen -Y verify`; the rest of this
document does not depend on which.

## 4. How the model's client talks to `pact`

`pact stdio` is an MCP server on stdio, which every MCP client can start.
Behind it `pact serve` is the MCP server proper. It implements `initialize`
(negotiating the protocol revision it knows), `ping`, `tools/list`,
`tools/call` and `notifications/cancelled`. It offers no resources, prompts,
sampling or roots, and answers any other method `method not found`. Its
`instructions` say what the service's say: a call may wait for the person's
approval until its deadline; `declined` and `refused` are decisions, do not
repeat them unchanged; `expired` and `unavailable` mean nothing happened,
**except `unavailable` with reason `no-answer`: the action may have run, do
not repeat it unchanged, ask the person if it is safe to repeat.**

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
  message is `unavailable`/`no-answer` (the verb may have run). What `pact`
  hands on to the model stays at 1 MiB of text content, as the service caps it;
  a final message that has more is a protocol violation and is treated the same.
- Progress is **not relayed** to the model's client in this version. Risk: an
  MCP client has a timeout of its own on a request, commonly reset by progress
  notifications; one that does not see progress may give up on a call whose
  person has not yet answered, though `pact` is still waiting. See "Not
  decided" (f).

## 8. What the model gets back

The service's tool result, normalised. Its first text content is one JSON
object `{"type":"outcome","outcome":...,"id":...,"reason":...}`
(agent-to-service.md section 6): `reason` only with `refused`, `rc` also in a
`done`. `pact`:

- parses it, and passes it on only if `outcome` is one of `done`, `declined`,
  `expired`, `refused` or `unavailable` and, for `refused`, `reason` is one of
  `not-allowed`, `invalid`, `try-later`. **Anything else becomes `refused` with
  `not-allowed`**, with a line on standard error: the closed list has no
  `unknown`, and "do not repeat" is the safe reading. It never passes on a
  string it received and did not parse into those words;
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
  - **`unavailable`/`no-answer`**: the call was sent and no answer came (the
    connection was lost, or the idle timeout, or an answer over the limits).
    **A verb may have run** (agent-to-service.md section 7). The text says so:
    "it may have run; do not repeat it unchanged; ask your person if it is safe
    to repeat". `no-answer` is not in the service's closed list and only
    `pact` can make it: "Not decided" (c);
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
   jq -nc --rawfile key agent --rawfile cert agent-cert.pub \
     '{v:1, key:$key, certificate:($cert|rtrimstr("\n")), deadline_seconds:5, min_wait_seconds:1,
       services:[{host:"localhost", name:"probe", url:"http://127.0.0.1:8443/mcp"}]}' > bundle.json
   ```

   and a function `p_act::pact::Bundle` (feature `pact`: builds, serialises and
   checks the same JSON), so that tests of p-robe and p-ledge do not each
   write it.
2. **Driving `pact` without an MCP client:** `pact call <tool> '<json>' <
   bundle.json` and `pact tools < bundle.json`, as in section 1; the result is
   the normalised tool result on one line, exit status 0 whenever `pact` itself
   worked (the outcome is in the JSON).
3. **The identifier and the call's hash on standard error** of every call, so
   that a test can find it in the service's audit line and in the fake
   pledge's log.
4. **A short `deadline_seconds` and a settable floor** in the bundle (above:
   5 and 1), so that a test of `expired` takes 5 seconds and not 120.
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
   `no-answer` and an unknown reason; a verb that runs for 60 seconds with
   keep-alive comments, which must not become `no-answer`; an answer of 3 MiB
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

## Not decided

These go to the designer, and (e) to the owner. Each has both sides and no
choice.

### (a) Signing in process, or by `ssh-keygen`

| | In process (`ring`) | `ssh-keygen -Y sign` |
|---|---|---|
| What the sandbox must contain | `pact` and nothing else of OpenSSH | `pact`, and OpenSSH's `ssh-keygen` (a package, with its own updates), on `PATH` or at a configured path; a writable directory on memory-backed storage for the key file |
| Where the key lives | in `pact serve`'s memory only; never in a file | in memory of `pact serve`, **and** in a file (mode `0600`, in a `0700` directory of `pact`'s user on a `tmpfs`) for as long as `ssh-keygen` may need it: from start to exit, or written and deleted around each signature. A crash leaves it until the tmpfs is gone; a child `ssh-keygen` opens it and could be observed or replaced if the path is writable by another |
| Code `p-act` must have | a **second SSHSIG writer** (the framing: `SSHSIG` magic, version, the certificate as public key, namespace, reserved, hash algorithm, the signature over the signed-data structure of magic, namespace, reserved, hash algorithm and the hash of the message) and an OpenSSH private-key reader (`openssh-key-v1`, unencrypted, one key; about 80 lines) | nothing new: `Signer` already does exactly this |
| What can go wrong | a signature that `ssh-keygen -Y verify` does not accept is loud: it fails every call. What is quiet is a difference in a rarely used case (hash algorithm, a certificate form), and any later change of OpenSSH's format | `ssh-keygen` missing, or another version, in the sandbox; a passphrase prompt (already prevented in `p-act`); the key on a file |
| Dependency | `ring` (already) | none new |

How the in-process writer would be kept honest against `ssh-keygen -Y verify`,
in `p-act`'s own tests, with real keys in a temporary directory as today:
(1) **Ed25519 signatures are deterministic**, so for the same key, certificate
and message the in-process armoured output can be compared **byte for byte**
with what `ssh-keygen -Y sign` writes; that is the strongest check there is,
and it runs for each namespace; (2) for ECDSA P-256 (not deterministic) every
signature is verified by `ssh-keygen -Y verify` and read back by
`signature_certificate`; (3) the same matrix as the existing tests, with and
without a certificate, many messages of different lengths including empty and
over 64 KiB, and the refusals (wrong namespace, changed bytes, expired
certificate) against the in-process signatures. A **third way** exists and I
did not test it: `pact` speaks the SSH agent protocol on a private socket
with the key in memory and runs `ssh-keygen -Y sign -U` against it. The key
then is in memory only and the framing is `ssh-keygen`'s, so there is no
second writer; it needs `ssh-keygen` in the sandbox, an SSH agent server of
about 150 lines in `pact` (identities, sign request), and I have not checked
that `-Y sign -U` signs with a certificate this way.

### (b) What the sandbox must give for the key to stay secret

`pact` lowers the exposure (no key file in the in-process case, nothing in the
model's context, nothing in its environment or arguments, `PR_SET_DUMPABLE` 0,
no core dumps). That is **not** secrecy from a model that can run code as the
same user. The requirement on the sandbox, precisely: `pact serve` runs as a
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

Who guarantees it: the sandbox (a user per role and the capabilities above) or
a written instruction to the person. If it is not given, the honest statement
is that the key protects against accident and against the model's text, not
against code the model runs as `pact`'s user. The threat table already says it
(approvals.md section 4: the sandbox is not trusted for the key's secrecy);
what is open is whether `pact` may rely on the sandbox for it.

### (c) `no-answer`

Only `pact` can say "I sent it and heard nothing"; a service cannot. The
service's closed list has `unavailable` with no reason, whose meaning is
"nobody could be asked, or nothing was done". The case: a verb started and the
answer was lost (agent-to-service.md section 7). Options:

1. **Add `unavailable`/`no-answer` to the closed list** as a reason that only
   `pact` makes. The model has one more word to understand, the list says it
   plainly, and the instructions can state the exception in one sentence. The
   list is no longer "what a service can say" but "what the model can be told".
2. **Report it as plain `unavailable`.** The list stays as it is. The model is
   then told "nothing was done", which is false here, and acts on it: it asks
   again and the verb runs twice. The warning could ride in the text content
   only; the outcome word is what a model acts on.
3. **A new outcome of its own** (for example `lost`), outside both: more
   distinct, a wider list.
Without a decision this document uses (1).

### (d) The bundle on standard input

The shape of section 2: one JSON object, one line. Alternatives for the
designer, with p-ledge:

- **A**, as proposed: key, certificate, services, settings and the TLS root in
  one object. One read, one version number, one parser. The key and the
  configuration are in one value, so a line that logs the bundle logs the key.
- **B**: the first line is the configuration (services, settings, root), the
  rest are the key and the certificate as they are in files (an OpenSSH private
  key block, then the `-cert.pub` line). The configuration can be logged and
  checked without ever holding the key; the key is the OpenSSH format
  unmodified, so a person can produce the second part with `cat`. Two parts to
  parse.
- Whatever the shape: a version number (`v`), unknown members refused, a size
  limit (64 KiB proposed), where it is specified (p-ledge) and who writes it
  (pledge, when the person starts the agent), and what happens to a bundle with
  a settable floor in production (the floor is for tests; a person should not
  be able to set the wait to 1 second by accident: perhaps the floor is a
  command-line option of `pact call`, not a bundle member).

### (e) For the owner: the HTTP client

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

### (f) Progress notifications

Whether `pact` should relay progress to the model's client, so that clients
that reset a request timeout on progress keep waiting. For: a person's answer
can take minutes and a client's default timeout is often shorter (commonly 60
seconds). Against: the service's progress text would be text from a service
into the model's context unless `pact` maps it to a fixed set of words ("handed
to your person's machine", "approved, running"), and a relayed message that
differs per client version is more to keep honest. Without it, a client that
gives up closes `pact stdio`, which is a cancel; the person's dialog is closed,
nothing ran.

## Dependencies, in short

For the library: unchanged (`serde`, `serde_json`, `base64`, `ring`,
`tempfile`, `thiserror`). For `pact` (feature `pact`): the choice of (e), and
`rustls` with its provider and `rustls-pki-types` for `https`; `libc` for the
one `prctl` call, in the binary only; the command line by hand (three
subcommands); threads and `std` sockets, no async runtime (at most 16 waiting
calls). In (a), the in-process option adds no dependency.
