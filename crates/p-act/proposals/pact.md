# `pact`, the agent's signer - a proposal

Status: a proposal for the orchestrator, the designer and the p-robe agent.
No code. Written against `doc/approvals.md` (section 10 decides `pact`),
`doc/approval-formats.md` (sections 1, 3, 3.1) and the service's side,
`crates/p-robe/proposals/agent-to-service.md` (the version that still says
headers; this proposal assumes the call rides in the tool call's `_meta`, as
approvals.md section 10 decided, and says where that matters). Terms as
approvals.md section 1: "agent" is the AI agent; the other thing is the "SSH
agent".

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

Two processes from one binary, because the key must arrive on standard input
(approvals.md section 10) and the model's MCP client wants to own the
stdio of the server it starts:

| Command | Does | Holds the key |
|---|---|---|
| `pact serve` | started by the person's SSH connection that starts the sandbox; reads one bundle from standard input (section 2), closes it, and stays. Listens on a Unix socket in a directory only its user may enter. Speaks MCP on that socket, and HTTP to the services | yes, in memory only |
| `pact stdio` | started by the model's MCP client as its "server"; copies bytes between its standard input/output and the socket. Reads no file and holds nothing | no |

Why not one process: the model's client starts `pact stdio` itself and may
start it many times; the key must not be on a command line, in an environment
variable or in a file the client's configuration names. Why not a loopback
port instead of a socket: anything else in the sandbox's network namespace
could reach it; a socket's directory has a mode. (A client that only speaks
HTTP can be given the loopback port as an option later; not in the first
version.)

**What the sandbox must give, and `pact` cannot:** the key stays secret from
the model only if the model's process cannot read `pact serve`'s memory or
its socket's directory. approvals.md section 4 trusts the sandbox for "no way
out except services" and explicitly **not** for keeping the key secret. So
`pact` lowers the exposure (no file, nothing in the model's context, no
`ssh-keygen`) and does `prctl(PR_SET_DUMPABLE, 0)` on Linux, but real
separation needs `pact serve` to run as another user than the model. That is
the sandbox's job; see "Open", 1.

## 2. What arrives on standard input

One JSON object on one line, then end of input:

```json
{"v":1,"key":"-----BEGIN OPENSSH PRIVATE KEY-----\n...","certificate":"ssh-ed25519-cert-v01@openssh.com AAAA...","services":[{"host":"a.example","name":"probe","url":"https://a.example:8443/mcp"}],"deadline_seconds":120,"tls_root":"-----BEGIN CERTIFICATE-----\n..."}
```

- `key`: an unencrypted OpenSSH private key, Ed25519 or ECDSA P-256 (other
  types refused, naming the type). `certificate`: its `-cert.pub` line, which
  must pass section 3.1 (`signature_agent` rules) and must be the key's own;
  checked at start, so a sandbox with a wrong pair fails at once, not at the
  first call. It must not be expired.
- `services`: the **only** services `pact` will talk to. `host` and `name` are
  what goes in `service` of each call; `url` is where to send it. Nothing in
  this list comes from the model. Stage 1 may leave `tls_root` out and use
  `http://` on loopback or a Unix socket URL (`http+unix`); anything else
  needs `https` and a root, which is the site's own (approvals.md section 5).
- `deadline_seconds`: the setting of section 5; at most 600, default 120.
- The bundle is put together by pledge when the person starts the agent
  (approvals.md flow A); p-ledge's specification owns the bundle's definition.
  This is a proposal for its shape.

`pact serve` refuses to start on any problem, with one line on standard
error that never contains key material.

## 3. Signing without `ssh-keygen`

The sandbox may have no `ssh-keygen`, and a key written to a file for
`ssh-keygen -Y sign -f` is a key on a disk. So `pact` builds the SSHSIG itself.
It is small: the `SSHSIG` blob of formats' `signature_certificate` in reverse
(the certificate as public key, namespace `call-v1@procession`, empty
reserved, hash `sha512`, signature over the `SSHSIG` signed-data structure),
armoured. `ring` signs Ed25519 and ECDSA P-256. The private key is read from
the OpenSSH container (`openssh-key-v1`, unencrypted, one key); that parser is
about 80 lines.

This code lives in `p-act` (feature `pact`, or always: it has no new
dependency, only `ring`), next to `Signer`, so that its signatures are tested
against the same real `ssh-keygen` verification as everything else: sign in
process, verify with `verify_call` for Ed25519 and P-256 keys, with and
without a certificate. A signature that `ssh-keygen -Y verify` does not accept
is a bug found by the test suite, not in the field.

Alternative, if the designer would rather not have signing code in `p-act`:
write the key to a `0600` file in a `tmpfs` directory of `pact`'s user, run
`ssh-keygen -Y sign`, delete at exit. Less code, key on a (memory) file, and
`ssh-keygen` required in the sandbox. I recommend the first.

## 4. How the model's client talks to `pact`

`pact stdio` is an MCP server on stdio, which is the shape every MCP client
can start. Behind it, `pact serve` is the MCP server proper. It implements
`initialize` (negotiating the protocol revision it knows; an unknown one gets
the nearest it supports), `ping`, `tools/list`, `tools/call` and
`notifications/cancelled`. It offers no resources, prompts, sampling or
roots, and answers any other method `method not found`. Its `instructions`
say what the service's `instructions` say (a call may wait for the person's
approval until its deadline; `declined` and `refused` are decisions; `expired`
and `unavailable` mean nothing happened, except `no-answer`, below).

Progress notifications from services are not relayed in the first version.

## 5. Which services exist, and the tool list

Services are exactly the `services` of the bundle. At the first `tools/list`
and then every 5 minutes (and never more often than every 30 seconds), `pact`
asks each service `tools/list`, which needs no call (agent-to-service.md
section 2), and builds its own list:

- **Names.** A client wants `[a-zA-Z0-9_-]{1,64}`. The tool a service offers
  as `rt_procs` is offered as `<name>__<host>__rt_procs`, the host with `.`
  replaced by `-` (`probe__a-example__rt_procs`), so that two hosts offering
  `probe` cannot collide. `pact` keeps the table name to (service, action)
  and refuses to start if two services of the bundle map to one prefix, or if
  a name would exceed 64 characters (the service's own tools are at most 64,
  so a long one is dropped with a line on standard error, not shortened).
- **A tool is accepted only if** its name, with `_` read as a space, is an
  action of the formats grammar (words `[a-z][a-z0-9-]*`), the name is
  unique, and its text passes the string rule of formats section 2.
  Anything else is dropped, not repaired.
- **The schema is `pact`'s, not the service's:** `params` (array of strings,
  at most 64, each at most 512 bytes), `claim` (string, at most 200
  characters), `wait_seconds` (integer, 1 to the setting); no other
  property. The service's own schema is advisory (agent-to-service.md section
  5 gives `pattern`s a model can use); `pact` passes a `pattern` for `params`
  items through only if it is a valid string of at most 512 characters, as
  `description`-like data, never interpreting it. The service refuses what its
  rules refuse in any case.
- **`description`** and `title` are the service's, cut to 1000 and 100
  characters and refused if they contain what formats section 2 refuses.
  This is text from a service into a model's context, which is a prompt
  injection channel; services are trusted to do what they say (approvals.md
  section 4), so `pact` bounds it but does not try to judge it. `annotations`
  pass through; the rating the service put in `_meta` is dropped (the model
  does not need it, and `_meta` is not the model's).
- `listChanged` is `false`. A service that is unreachable at refresh time
  keeps its last list; one never reached offers no tools, and `pact` says
  so on standard error.

## 6. Composing the call from a tool call

For `tools/call` with `name`, `arguments`:

1. Unknown name, or `arguments` with any member but the three above, or a
   member of the wrong type: an MCP error result (`isError`), nothing is
   signed. Not an outcome: it is the model's mistake, said plainly
   ("params must be an array of strings").
2. `service` is the table's `{host, name}`. `action` is the table's.
   `params` and `claim` are the model's, as given (no trimming, no
   re-encoding); `Call::compose` applies the formats' limits and string rule,
   and a refusal is the same MCP error, with the `ParseError` text (it says
   which member and why, and contains nothing secret).
3. `id`: a fresh version 4 UUID from the operating system's random source
   (`ring::rand`, no new dependency), per tool call, never reused, and
   **never sent twice**: a transport failure is never answered by sending the
   same call again. The model may make a new tool call, which is a new call.
4. `deadline`: now plus `min(wait_seconds, setting)` if the model gave
   `wait_seconds`, else now plus the setting. The model can shorten the
   wait and never lengthen it; a longer `wait_seconds` is not an error, it is
   clamped, because the schema says the limit and the model should not be
   punished for rounding. The setting is the bundle's `deadline_seconds`,
   at most 600 (the services refuse more than 10 minutes).
   The sandbox's clock is the one that decides; services tolerate 60 seconds.
   If a service answers `deadline-past` or `deadline-too-far` for a call whose
   deadline was set from the setting, that is a clock fault: `pact` says so
   once on standard error.
5. Sign (`call-v1@procession`), then send `tools/call` to the service's URL
   (section 7) with the tool's `name` as the call's action with spaces
   replaced by `_`, `arguments` = `{params, claim}` exactly as signed (`claim`
   absent if the call has none; `wait_seconds` is dropped, it was `pact`'s),
   and `_meta` carrying the call's bytes and the signature, each base64 (the
   same values as the request's `call` and `call_sig`, formats section 4). The
   member names of `_meta` are a question for the connections document
   ("Open", 2); this proposal assumes
   `_meta."procession"` = `{"call": ..., "call_sig": ...}`.

`arguments` must equal the signed call (approvals.md section 10); `pact`
builds both from the same `CallContent`, so it cannot differ.

## 7. Talking to a service

HTTP/1.1, one request per connection (`Connection: close`), a thread per call
waiting (at most 16 at once, as the service's own limit; more are answered
`unavailable`/`no-route` at once). Blocking sockets, no async runtime.

- Only the configured `url`s. No redirects are followed (a redirect is
  `unavailable`). No proxy variables are read. No credentials in the URL. The
  `Host` header is the configured one. `https` verifies the service's
  certificate against `tls_root` and the configured host name, nothing else.
- Responses: `application/json` or `text/event-stream` (the service may stream
  for progress); `pact` reads either, takes the one JSON-RPC response whose
  `id` is the request's, and ignores the rest. Body at most 1 MiB; a longer
  one is `unavailable`/`no-answer`. Content-Length and chunked encodings.
- Timeouts: connect 10 seconds; the read waits until the call's deadline plus
  10 seconds, because the service answers `expired` itself at the deadline.

## 8. What the model gets back

The service's tool result, normalised. The first text content is the one JSON
object `{"type":"outcome","outcome":...,"id":...,"reason":...}` of
agent-to-service.md section 6. `pact`:

- parses it and passes it on only if `outcome` is one of `done`, `declined`,
  `refused`, `expired`, `unavailable` and `reason` is in the closed list of
  that document; anything else becomes `refused` with `unknown`, with a line
  on standard error. It never passes on a string it received and did not
  parse into those words;
- passes the answer of a verb (`done`) on as the further text contents, up to
  1 MiB, unchanged: that is the data the model asked for;
- makes its own outcomes for what happens on its side, with the same shape and
  `id`:
  - `refused`/`invalid-call`: only for what a service said about the call; a
    model mistake is an MCP error (section 6), not an outcome;
  - `unavailable`/`no-route`: nothing was sent, or the service refused the
    connection, answered 5xx or `503`, or the TLS check failed. Nothing was
    done;
  - **`unavailable`/`no-answer`**: the call was sent and no answer came (the
    connection was lost, or the wait ended). **Here a verb may have run**
    (agent-to-service.md section 7: a verb that started finishes and its
    answer is lost). The text says so: "it may have run; do not repeat it
    unchanged; ask your person if it is safe to repeat". This is a reason that
    list does not have; I propose adding it, "Open", 3;
- on `notifications/cancelled` from the model, closes the connection to the
  service (which is the service's cancel, agent-to-service.md section 7) and
  answers nothing further.

No HTTP status, header, body of an error, TLS message or system error text
reaches the model, only the words above. Detail goes to standard error (the
sandbox's log), without key material, and with the call's `id` and hash but
not its parameters.

## 9. What `pact` must never do

- Show the key: not in output, errors, logs, arguments, the environment,
  `/proc` listings (key only in memory, `PR_SET_DUMPABLE` 0, the bundle read
  once and the buffer wiped), crash messages (`panic = "abort"` with a fixed
  message for the `pact` binary), or any tool.
- Sign anything but a call that it composed itself from a tool call. There is
  no tool, method or socket message that takes bytes to sign, and the
  namespace is fixed in code, so it cannot make an approval or a clearance
  signature by being asked cleverly. The signing function takes a `Call`, not
  bytes.
- Talk to anything but the configured services: no URL from the model, no
  redirect, no second host, no DNS name but the configured one, no
  environment-chosen proxy.
- Send a call twice, lengthen a deadline, or reuse an identifier.
- Write to disk, other than the socket's directory entry, or read any file
  after start. All configuration arrives on standard input.
- Trust the answer: it is a model's input, bounded in size, and `pact` does
  not act on it.

## 10. Dependencies

In the local registry (crates.io is blocked here), on this machine, today:

| Need | Choice | In registry |
|---|---|---|
| JSON, base64, errors | `serde`, `serde_json`, `base64`, `thiserror` | already (the library uses them) |
| signing, random, hashing | `ring` (Ed25519, ECDSA P-256, SHA-512, `SystemRandom`) | already |
| HTTP | **none usable as a client**: no `ureq`, `reqwest`, `hyper`. A small HTTP/1.1 client by hand over `std::net::TcpStream` and `std::os::unix::net::UnixStream`, with `httparse` for the response head | `httparse` 1.10.1 yes |
| TLS | `rustls` 0.23 with the `ring` provider, `rustls-pki-types` (PEM), `rustls-webpki` | present in the registry (not all unpacked here; to confirm with a build) |
| Unix `prctl` | `libc` (one `unsafe` call, in the binary only) or none | `libc` yes |
| command line | by hand; three subcommands | none |
| threads, sockets | `std` | none |
| async | not needed: at most 16 waiting calls, a thread each | (`tokio` present, not used) |

New for the feature `pact` only: `httparse`, `rustls`, `rustls-pki-types`,
`libc`. The library's dependencies do not change. A hand-written HTTP client
in a program that holds a key is a risk; I would keep it to the subset in
section 7, give it its own tests (chunked, SSE, oversized, truncated,
redirect, wrong host name), and not make it general. If the owner prefers a
vetted client crate, `ureq` is the natural one and would have to be added to
the local registry first.

## 11. Tests

- Against a fake service in the test (a `TcpListener` on loopback, no
  network): `pact serve` gets a bundle with a real `ssh-keygen`-made
  delegation and agent certificate, a model's `tools/call` goes in on the
  socket, and the fake service verifies `_meta` with `verify_call`, parses
  the call with `Call::parse`, and checks `arguments` equal the call, the
  deadline is within the setting, the id is a new UUID each time, and nothing
  is sent twice after a dropped connection.
- Each outcome of section 8, including `no-answer`, a service's unknown
  reason, an oversized answer, a redirect, a wrong host name, and a service
  that answers for another id.
- The refusals of section 6 (extra argument, `params` of numbers, 65 params,
  a claim with a control character) sign nothing: the fake service sees no
  connection.
- A key that does not match its certificate, an expired certificate, a
  certificate with a critical option, an RSA key: `pact serve` refuses to
  start, and its standard error contains no part of the key.
- The in-process signature verifies under `ssh-keygen -Y verify` (section 3).

## Open

1. **The key's secrecy from the model.** Needs `pact serve` to run as a
   different user than the model, or the sandbox to deny `ptrace` and
   `/proc/<pid>/mem`. Who guarantees it: the sandbox, or `pact`'s
   instructions to the person?
2. **`_meta` member names** (connections document), and whether the service
   expects `wait_seconds` or not (this proposal drops it; the service's
   proposal says "not acted on").
3. **A reason `no-answer`** for "sent, and the answer was lost". Without it,
   `unavailable` would tell the model that nothing happened, which is false.
4. **The bundle's shape** (section 2) belongs with p-ledge's specification.
5. **Tool names with the host in them** (section 5): acceptable to the p-robe
   agent, or should a single configured service be offered without prefix?
6. **Where signing code lives**: `p-act` (recommended), or pledge's crate.
7. **TLS in stage 1**: plain `http` on loopback or a Unix socket is enough
   there; `https` and the root belong to stage 2 or later.
