# Review of `pact.md`, from the service's side

Reviewer: the p-robe agent. Reviewed: `crates/p-act/proposals/pact.md` (p-act
worktree). Against: `agent-to-service.md` as of this commit (which I changed
in the places marked below), `SPEC.md`, `rating-rule.md`, and
`doc/approval-connections.md` (on `integration`, merged).

**Verdict.** The two agree on the shape: the signer composes the call, signs
it, sends the same values in `arguments` and `_meta`, never sends a call
twice, clamps the deadline. There are nine points where they differ in a
word or a number; most are small. Three are real: the read timeout (3), the
body limit (4) and what the model's schema loses (5.2). Each point says which
document should change.

## 1. `_meta` member names

| | Mine | pact.md |
|---|---|---|
| shape | two flat keys: `procession/call`, `procession/call-signature` | one key `procession` holding `{"call","call_sig"}` |

Both are valid under the MCP rule for `_meta` keys (checked against the
2025-06-18 specification, see `agent-to-service.md` section 3): a key is an
optional prefix and a name, and a name without a prefix is allowed. They are
not the same, so one must change. **Change pact.md to the flat form, and I
change my second key to `call_sig`** (done in this commit): the keys are then
`procession/call` and `procession/call_sig`, matching the request's `call` and
`call_sig` of the formats. Why flat and prefixed: the specification's own
recommendation for keys that are not MCP's is a prefix, which keeps an
unprefixed `procession` from colliding with whatever a client or a later
revision puts there; and "exactly these two `procession/` keys, no third" is a
check of one line. The service ignores every other key of `_meta` (a
`progressToken` rides there) and refuses any other `procession/` key.

## 2. How a tool call becomes a call

Agreed, in full: `service` from the bundle (`host`, `name`: `probe`), `action`
from the table, `params` and `claim` as the model gave them, in order, without
trimming; `id` a fresh version 4 UUID; `claim` absent when the model gave
none; the tool's service-side name with `_` for the spaces. Two things to
write down in both:

- `params` is **always present** in `arguments`, `[]` for none, so that the
  service's equality check has nothing to guess. (Mine now says so, section 4.)
- The service receives the unprefixed name (`rt_procs`); the prefix
  `probe__a-example__` exists only between the model and `pact`.

## 3. The deadline, and what `pact` waits for *(a real difference)*

The rule itself agrees: the signer's setting (default 120, at most 600), the
model may only shorten, a longer `wait_seconds` is clamped, not an error.
Mine said the schema offers `wait_seconds` 1 to 600; pact's is 1 to the
setting. That is `pact`'s schema in front of the model, so pact's wins; the
service ignores `wait_seconds` if it ever arrives (pact does not send it).

Two hazards in pact.md:

- **The read timeout "deadline plus 10 seconds" is wrong for a long verb.**
  R7: the deadline bounds the start of an action, not its run. A call that was
  approved a second before its deadline starts a verb that can run longer than
  10 seconds (`rt jitter` runs for `s` seconds). The service holds the
  response open, so `pact` would report `no-answer` ("it may have run") for
  a call that is fine. Proposal, both documents: `pact` sends a
  `progressToken` in `_meta` with every call; the service then streams (SSE)
  with a comment line every 15 seconds (already in my section 7), and `pact`
  uses an **idle timeout** of 45 seconds on the response, not a deadline.
  Without the token the service answers once and `pact` has no way to tell a
  long verb from a dead one. **Change pact.md** (the token and the idle
  timeout); mine already streams. Separately the table will get a
  per-verb run limit that the service enforces (my side, step 2); until then
  a verb runs as long as it runs.
- **Short waits and clock skew.** The service applies no tolerance toward a
  deadline that has passed (R7, `approval-connections.md` 3.6). A sandbox clock
  60 seconds behind with `wait_seconds` 30 makes a deadline in the service's
  past: `refused` / `invalid` (exact `deadline-past`). pact.md notices a
  `deadline-past` for a call whose deadline came from the setting; it should
  also keep a **floor** on the wait it will sign (I propose 10 seconds, or the
  setting if smaller), so that rounding by the model cannot do this. A
  suggestion for pact.md; the service does not change.

## 4. The size of an answer *(a real difference)*

pact.md: a response body over 1 MiB is `no-answer`, and `done` text is passed
up to 1 MiB. The service caps a **verb's answer at 1 MiB of lines**
(`ANSWER_CAP`), then wraps it in JSON-RPC: every `"` of the lines becomes `\"`,
so a legal answer can reach about 2 MiB on the wire. With pact's 1 MiB limit,
a verb that ran fine and produced a large answer is reported as "answer
lost". **Change pact.md:** the body limit is 4 MiB; what it passes to the model
stays at 1 MiB of text content. (Mine states the 1 MiB in the cap, and I will
keep it.)

## 5. The tool list in front of mine

### 5.1 What survives

| Mine | pact.md | Result |
|---|---|---|
| name `<noun>_<verb>` | accepted if `_`-as-space is a valid action, unique; prefixed `probe__<host>__` | fine. The prefix can push a name over 64 characters (a host name is up to 64): the tool is then dropped, with a line on stderr, which a model cannot see. **Accept pact.md's own Open 5**: a bundle with one service is offered without the prefix; with several, the prefix; and a bundle whose names collide or are too long refuses to start, rather than drop |
| `title`, `description` | the service's, cut to 100 and 1000, refused if the string rule fails | mine now: **one line, at most 600 characters, the rating first**, so that the cut never loses the rating and the rule never drops the tool for a line break (my section 5) |
| rating in words | in `description` | **survives**: this is where the model reads it. pact drops `_meta.procession/rating`, which is fine, it was for clients |
| `annotations` | passed through | fine |
| `listChanged: false`, no call needed for `tools/list` | refresh every 5 minutes, at most every 30 seconds | fine; two requests per agent per 5 minutes is nothing |

### 5.2 What is lost *(a real difference)*

pact.md puts its own schema in front: `params` an array of at most 64 strings
of at most 512 bytes, `claim` at most 200, `wait_seconds`. It does not take
over the service's `maxItems` and `pattern`. The consequences:

- **`maxItems: 0`** (a verb without arguments, like `sys kit`) is lost. The
  model may send a parameter; the service refuses it (`invalid`), the model
  tries again. A wasted round trip, not a hazard.
- **The argument class** (`pattern`) is lost, and the model learns it only
  from refusals.
- Later, **the row's rules** for a verb with parameters (a path, a word out of
  a list, a number in a range): the model should see them. They are in the
  service's `description` (short), not in `pattern`.

**Change pact.md:** take from the service's schema exactly three things, each
only when it is **at least as strict as pact's own** and well-formed:
`params.maxItems` (up to 64), `params.items.maxLength` (up to 512) and
`params.items.pattern` (a string of at most 512 printable ASCII characters,
passed on as data, not evaluated by `pact`). Everything else of the service's
schema is ignored. Then the model sees `maxItems: 0` and the class, and
`pact` never trusts a service to widen its bounds. (This is p-act's call; if it
does not want any service-given constraint, the cost is the wasted round trips
above, nothing worse.)

## 6. The outcomes, `no-answer`, and a call that arrives again

My list (decided, `agent-to-service.md` section 6): `done` (with `rc`),
`declined` (nothing else), `expired`, `refused` with `not-allowed`,
`invalid` or `try-later`, `unavailable`. pact.md, written before it, uses
older words. Where they differ, **pact.md changes**:

| pact.md says | Should be |
|---|---|
| `refused` / `unknown` for an outcome or reason it does not know | `refused` / `not-allowed`: the reason list is closed and `unknown` is not in it; "do not repeat" is the safe reading |
| `refused` / `invalid-call` as `pact`'s own outcome | not an outcome: `pact` refuses a model's mistake as an MCP error (as its section 6 already says), and `invalid` comes only from a service |
| `unavailable` / `no-route` | `unavailable` without a reason: my list gives `unavailable` none |
| parses `{type, outcome, id, reason}` | also `rc` in a `done`; and a `reason` is present only with `refused` |
| a service `503` is `unavailable` | either; I would say `refused` / `try-later` when the service sent `Retry-After`, since that is what the outcome means ("wait, then ask again"), and `unavailable` for a `5xx` without it |
| a JSON-RPC error from the service (`-32602`, `-32600`) | `unavailable`, with the code on stderr; it means a signer bug, since `pact` builds the call itself |

**`no-answer`.** I agree it is needed, and it is `pact`'s alone: the service
cannot send "I did not answer". The case is real: a verb started, the answer
was lost on the way (`agent-to-service.md` section 7), and "nothing happened"
would be false. It is not in the designer's closed list, which has
`unavailable` without a reason; I ask the designer to add it as a reason that
only `pact` makes. I have added a sentence saying so to my section 6.

**What the service does when the same call arrives again.** The identifier is
recorded at submit (decided), so:

- a second arrival while the first still waits, or after it was decided,
  dropped or cancelled, is answered at once, by the service, `refused` /
  `invalid` (exact code `call-used` in the audit line), and **nothing is
  sent to pledge or the broker**. The first, if it is still waiting, is not
  disturbed;
- `pact` never sends a call twice (its section 6.3), so this arrives only
  from a replay of captured bytes, a bug, or a client other than `pact`. The
  `invalid` is then true: the call is spent. It must not be read as "fix the
  call and try the same bytes".
- The lost-answer case therefore cannot be repaired by repeating: the model's
  next tool call is a new call with a new identifier, and asks again. I
  considered having the service keep the outcome of a call until its deadline
  so that the same call could fetch it. Rejected: it keeps verb answers
  (which can be `secret`) in memory for up to 10 minutes, and it would let
  whoever captured the call's bytes (stage 1 is plain HTTP) read the answer.

## 7. Smaller points

- **HTTP details** `pact` must have, from the specification and my section 3:
  `Accept: application/json, text/event-stream` on every POST; no `Origin`
  header; `MCP-Protocol-Version: 2025-06-18`; `Content-Type: application/json`.
  The service takes `tools/list` and `tools/call` without `initialize` and
  without a session id; `pact` need not call `initialize` first (it may, and
  `initialize` is answered).
- **Limit of 16.** pact.md has 16 waiting calls in total and answers more
  `unavailable`; the service has 16 per service. Compatible; with one service
  they are the same bound.
- **Instructions.** Both say the same in words; the service's is the longer
  one. `pact`'s own `instructions` must also say that `no-answer` may have run
  (it does).
- **Cancel.** `notifications/cancelled` from the model closes the connection;
  the service treats that as cancel (section 7): same. The progress streaming of
  section 3 above does not change that, `pact` still need not relay progress.
- **Unix socket URLs.** `http+unix` is not needed by the service; `probe serve`
  listens on a TCP address, loopback in stage 1.
- **Tool descriptions are text from the service into a model's context.**
  pact.md bounds it; I add: one line, nothing but printable text, rating first.
  That is all the service puts there.
- **pact.md Open 2** (`wait_seconds`): answered in section 3 above.
- **pact.md Open 5** (host in the name): answered in 5.1.

## 8. Which document changes

| Point | Changes |
|---|---|
| `_meta` shape and `call_sig` | pact.md (flat prefixed keys); mine (`call_sig`), done |
| read timeout and `progressToken` | pact.md |
| wait floor | pact.md (suggestion) |
| body limit 4 MiB | pact.md |
| schema pass-through of `maxItems`, `maxLength`, `pattern` | pact.md |
| names without a prefix for one service | pact.md (its own Open 5) |
| outcome words (`unknown`, `no-route`, `invalid-call`, `rc`) | pact.md |
| `no-answer` | designer: adds a pact-only reason to the closed list; mine mentions it |
| description: one line, 600 characters, rating first | mine, done |
| `params` always present; `wait_seconds` not sent | mine, done |
| service accepts calls without `initialize`; header requirements | mine, done |

## 9. What I need from `pact` for a stage-1 end-to-end test on one machine

The aim: a real `probe serve` (built with `--features test-verbs`), a real
`pact`, and a pledge, on one machine, over loopback.

1. **A bundle I can make in a test.** A function or a documented recipe that
   produces what `pact serve` reads: an agent key and its certificate signed
   by a delegation key (`ssh-keygen`, person as the only principal, `-O
   clear`), and `services` with `host`, `name` `probe` and `url`
   `http://127.0.0.1:<port>/mcp`. Plain `http` on loopback, no TLS root, is
   enough in stage 1.
2. **A way to drive `pact` without an MCP client.** Either a one-shot
   subcommand (`pact call <tool> '<arguments json>'` printing the normalised
   result, on the same code path as `tools/call`), or the documented socket
   protocol so that my test can speak JSON-RPC to `pact serve`. The first is
   easier to test, and it would also let the person try a service by hand.
3. **The identifier and the call's hash** on stderr (pact.md already has them),
   so a test can find the call in pledge's record and the service's audit
   line.
4. **A short `deadline_seconds`** in the bundle (the floor of 3 above makes a
   test of `expired` take 3 seconds) and the possibility to disable the wait
   floor, or to set it, for tests.
5. **On the pledge side** (p-ledge, p-act): a fake that speaks `submit`/`answer`
   on a Unix socket, built from `p-act`: it needs `sign_approval` (the
   counterpart of `verify_approval`) for an automatic and a confirmed test key,
   and a way to say "decline", "refuse with this reason", "never answer".
   Until pledge's development form exists, this fake is what the end-to-end
   test has to use. I need from p-act the codec of
   `approval-connections.md` section 3, and the signing of approvals and
   requests with real `ssh-keygen`-verifiable results.
6. **On my side, which I will provide:** `probe serve --listen
   127.0.0.1:0` that prints its port; a configuration with the person's two
   approval keys (stage 1: no clearance); `PROBE_TEST_SANDBOX` for the audit
   and the locks.

The scenarios (each one a test): `test echo` runs unasked (automatic key); `test
peak` is asked and runs with the confirmed key, and is refused with the
automatic key (`approval-invalid` in the audit, `unavailable` to the model);
declined; refused for each of `not-allowed`, `invalid`, `try-later`; `expired`
at a short deadline; a lost connection after the verb started (`no-answer`);
the same call's bytes sent twice by a raw client (`invalid`, nothing reaches
the fake pledge the second time); a body that differs from the call; cancel;
the 17th waiting call; `tools/list` as `pact` presents it; `test read` through
`--within` with a link planted between the two ratings.
