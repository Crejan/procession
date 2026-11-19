# p-robe - specification (draft)

A host's diagnostics as a fixed table of rated verbs, and the service that
offers them to agents and asks before it acts. Binary `probe`.

It is the successor of `diag-tools` (Python): the same idea, a fixed table of
small verbs behind one dispatcher. Two things change. The verbs are no
longer programs of their own but calls into the other tools of this
workspace. And an agent no longer enters with one shared key that names no
person: each call leads to a request that the agent's person approves on
their own machine. `diag-tools` stays as it is until this has replaced it.

The approval system is [`doc/approvals.md`](../../doc/approvals.md); this
document uses its terms (its section 1). A **verb** is what that document
calls an action: one row of p-robe's table.

License: MIT OR Apache-2.0.

Status: the dispatcher exists with the table below; of its verbs only
`sys kit` runs, the others wait for `prover`. The service (`probe serve`)
does not exist. The name is a working name. It is not p-rover's
subcommand `probe`, and it is not what `diag-tools` calls a probe (a
measurement that loads a host); if that stays confusing, the name goes.

## Scope

- One host. The verbs answer questions about that host.
- Two callers: an agent, through the service; a person, through the
  dispatcher.
- Non-goals: no collectors of its own (they are the other tools'); no rules
  about who may what (the broker's); no shell and no session for anyone; no
  verbs about a site as a whole (monitoring, the directory) in the first
  version.

## The two parts

```
sandbox                              host
agent ──call (MCP)──▶ probe serve ──request──▶ broker ──▶ the person's pledge
                          │         ◀──approval, clearance──
                          ▼
person ──sudo──▶ probe <noun> <verb> ──▶ prover, pusher, player, plumber, preserve
```

**The dispatcher** (`probe <noun> <verb> [args]`) runs one verb. It is what
`diag-dispatch` is today: tokens checked against a fixed character class, no
shell between caller and verb, one JSON object per line (a header, then the
findings), a cap on every answer, a line in syslog before and after each
call, and a call whose first line cannot be written does not run.

**The service** (`probe serve`) is what an agent talks to. For each call it
states a request, obtains approval and clearance, checks them, and only then
runs the dispatcher. It signs requests with a key of its own, for which the
host's key issued a certificate when the service was installed; it never
reads the host key. That certificate is valid 30 days. `probe setup`, run
as root, makes it, and is the same command for the first time and for
every renewal: it keeps the service's key and replaces the certificate. A
root timer on the host runs it daily in a form that renews only when due:
it does nothing while more than 10 of the 30 days remain, and renews
otherwise, or at once when there is no certificate or the key changed. A
renewal that fails ends non-zero, so the timer's unit shows as failed and
the next day tries again. Run by hand, `probe setup` renews always. Nothing
from outside the host is an argument to it, and no converge is needed. `sys kit` reports the days
left, and fewer than 5 is a warning. **The lock and the deadline.** The dispatcher takes one lock per calling identity, so one call per
identity runs at a time. A call that comes through the service (`--call <uuid>`) waits for it, up to
about 10 seconds; by hand, without `--call`, a held lock is "busy" at once. The service passes the
call's deadline unchanged (`--until <seconds>`: seconds since the epoch, UTC, to the second, never a later
time), and **the dispatcher enforces it**: it refuses one more than ten minutes ahead of its own clock (660
seconds, the 60 seconds of tolerated clock difference applied as the service applies it), and it cuts its wait there and,
after it holds the lock, checks the clock again and does not start the verb at or after the deadline
(exit 76; the agent hears `expired`). The service enforces its part too: it starts the dispatcher only
while the deadline has not passed. Still held after the wait: exit 75, `refused / try-later`, and the
audit line says that it waited and for how long. The deadline bounds the start of a verb, not its run.
The service runs under an account of its own, and the dispatcher
gets the privilege each verb needs through the same sudo rule a person's
call uses. It holds no rule about who may what. It does hold the ratings: they are facts about its own verbs, and
rating them is its responsibility.

## Who may call

- **An agent**, only through the service, with an approval for every call.
  An agent runs in a sandbox (`doc/approvals.md`, R2): it has no account on
  this host and cannot reach the dispatcher.
- **A person**, through the dispatcher under their own login, by a sudo rule
  the site writes for that one path, as today. No approval: the person is
  there and acts themselves. That grant has nothing to do with agents: which
  groups' agents may use this service is the `groups` parameter of the
  service's binding in the site project (`doc/approvals.md`, R10), and the
  broker checks it.

The dispatcher refuses the verb `run command` (below): a person who may run
commands has sudo for that and needs no detour, and the detour would hide
the command from sudo's own log.

The shared agent key of `diag-tools`, its command account and the window
that `diag-remote open` writes go away with it.

## Verbs

A verb is a row in one table: noun, verb, the program of this workspace that
does the work, its rating, a summary. The catalogue, the wording of the
approval dialog and what the site's sudo rule may name are derived from that
table.

- **Built on this workspace.** A verb calls `prover`, `pusher`, `player`,
  `plumber` or `preserve`. **The dispatcher wraps what the tool prints; the
  tool keeps its own format and gets no second one.** How, for `prover`, is in
  "A verb that runs `prover`" below.
- **Rated for the worst case** (`doc/approvals.md`, R4). The table holds
  each verb's worst rating over every parameter it accepts. For a concrete
  call the service may rate lower only by a rule that stands in the table
  beside the verb, never higher, and at the top where it cannot tell.
- **`run command`**, for agents only: one command, stated in full, run once
  without a terminal and without input, with a time limit and a cap on its
  output. Rated at the top of every scale always, so it is never approved
  automatically. It exists so that a missing verb does not become a reason
  to give an agent a login. Stage 4.

## A verb that runs `prover`

`prover` prints **one JSON object** (its own SPEC: `schema_version`, `subcommand`,
`host`, `started_at`, `mode`, `cost`, `unreadable`, `records`, `restored`,
`findings`) and exits 0, 1, 2, 3 or 4. The dispatcher is the boundary: it owns
the byte cap and the line convention, and `prover` is changed for neither.

**The row** names the whole fixed command: the absolute path (`/usr/local/bin/prover`),
the words that never change (`irq --format json`), a map from each agent-facing
parameter to the flag it becomes, the `subcommand` the object must carry, and
which exit codes are results. Nothing from an agent is placed in the command but
the mapped values, as plain words the dispatcher puts after the flag it chose; no
argument of an agent starts with `-`, as everywhere. The tool runs with a cleared
environment, no standard input, as root through the same sudo rule.

**The agent-facing parameters**, plain words (`key=value`), each a number in a range
the row states:

| Verb | Parameter | Becomes | Range |
|---|---|---|---|
| `rt procs` | `max=N` | `--max N` | 1 to 10000 |
| `rt irq` | `duration=N` (seconds) | `--duration Ns` | 1 to 30 |
| `rt irq` | `top=N` | `--top N` | 1 to 1000 |

Both are optional and contribute nothing to the rating (`prover procs` and
`prover irq` read; they change nothing).

**The dispatcher reads the object with a size limit of its own** (4 MiB), parses it
and checks it is the object the row expects (`schema_version` 1, `subcommand` the
row's). It then writes the output convention, one JSON object per line:

1. the header (`type` `header`, `schema_version`, `noun`, `verb`, `host`, `ts`) with
   the tool's `subcommand`, `started_at`, `mode` and `cost` added;
2. one line per entry of `unreadable`: `{"type":"unreadable","source":...,"reason":...}`
   (what the tool could not read, so that an agent does not take a hole for an empty
   place);
3. one line per entry of `records`, **as the tool wrote it** (it carries its own `type`);
4. one line per entry of `restored` (`type` `restored`);
5. one line per entry of `findings`: `{"type":"finding","id":...,"severity":...,
   "subject":...,"evidence":...,"recommendation":...,"changes":...}`;
6. the trailer: `{"type":"trailer","rc":N,"result":"info|warnings|critical|failed-diagnostic",
   "records":n,"findings":n,"unreadable":n,"truncated":false}`.

The types `header`, `unreadable`, `restored`, `finding`, `trailer` and `error` are the
dispatcher's: a record of the tool with one of them is a disagreement (below). The
cap of 1 MiB on the answer (`ANSWER_CAP`) is part of the line convention of **every** verb, not of
these rows only: it applies to everything before the verb's **closing record** (a `prover` row's trailer, `sys kit`'s
`summary`). A line that would pass it, and every line after, is not written but counted. Then comes the
`truncated` record (`limit_bytes`, `dropped_lines`, `dropped_bytes`, `dropped`: the counts by record `type` for
the eight most numerous types, `others`: the rest) and then the closing record, **always**: it carries the tool's
`rc` and `result` and the counts of what the tool reported (`records`, `findings`, `unreadable`), not of what was
sent, and `truncated: true`. So a cut answer cannot be read as "no findings". Out of the cap 1024 bytes are kept
for the `truncated` record and 2048 for the closing record (`TRUNCATED_MAX`, `CLOSING_MAX`); a verb that goes on
writing after the cut is not stopped, which is how the counts are complete. (`prover`'s own estimates, about 115 KB
for `procs` and 150 KB for `irq`, are far below.)

**Exit codes.** The dispatcher's own exit code says only what the dispatcher did: 0 it
ran, 64 refused, 75 busy, 76 expired, 3 no audit line could be written. **The tool's
code never becomes the dispatcher's**; it travels in the output, as `rc`:

| Tool exit | The call | In the output |
|---|---|---|
| 0, 1, 2 (the row's result codes: nothing above info, warnings, critical) | `done` | the lines above, trailer `rc` 0/1/2 and `result` `info`/`warnings`/`critical` |
| 3 (the diagnostic itself failed) | `done` | the lines the tool gave, trailer `rc` 3 and `result` `failed-diagnostic`: an agent must not read an empty answer as "all fine" |
| 4, any other code, a signal, a timeout, a tool that cannot be run | **failed** | no tool lines; one `error` record with a `code` (`tool-refused` for 4: the row and the tool disagree about the arguments; `tool-failed`, `tool-killed`, `tool-timeout`, `tool-unusable`), then the trailer with `rc` null and `result` `failed` |
| not one JSON object, **an object with a repeated key at any depth** (`duplicate-key`: refused, neither the first nor the last taken; read by `p_ermit::json`, which echoes no value), over the limit, the wrong `subcommand` or `schema_version`, a record of a reserved type | **failed** | no tool lines; one `error` record (`not-an-object`, `object-too-large`, `wrong-object`, `reserved-type`), trailer `result` `failed` |

A failed call never ends with half an output. The dispatcher's exit code for a verb that was
started and did not produce a usable result is **70** (decided; not 2): a tool code outside the row's
result codes, a signal, a timeout, a bad or too large object, a reserved record type. The `done` audit
line carries `rc=70` and `cause=` (`tool-refused`, `tool-failed:N`, `tool-killed:N`, `tool-timeout`,
`tool-unusable:why`, `not-an-object`, `duplicate-key`, `object-too-large`, `wrong-object`, `reserved-type`; for a verb of this
program `verb-code:N` and `answer-lost`). The service tells the agent `failed` (not `unavailable`: that is
only for a verb that certainly did not start) and logs the cause under the call's identifier.

**Built** (`src/prover.rs`): `rt procs` (`max`) and `rt irq` (`duration`, `top`); the limit on the object is
4 MiB, the tool's run is killed after 30 s (`procs`) or 60 s (`irq`: the longest window and then some), and
the tool is not run at all unless, for root, the file where its name leads (links resolved) **and every directory above it**
are owned by root and cannot be written by group or others (`tool-unusable`). **Where `prover` is:** the fixed `/usr/local/bin/prover` (`PROVER_PATH`, one constant, which packaging may change
at build time; never a setting: the dispatcher runs it as root, so nothing an account can edit may name it),
installed beside `probe` by the roll-out. `sys kit` reports the path and, if it cannot be run, a warning. `rt jitter` stays unbuilt.

**`host_text` through sudo (decided, to build).** A row whose output can carry text that is not the service's (`rt procs`,
`rt irq`, `test read`, `sys kit`; later `run command`; not `rt jitter`) is marked `host_text: true` in the table, in
`probe catalog` and in the tool's `_meta` (`procession/host_text`, required, for every tool; `pact` words the warning, not the description). The request carries the mark, signed with the rating, and it goes through sudo as
the **fourth token of `--within`**: `--within open,none,none,text|plain`. Four tokens are required: a value of three is refused
(64) so that an old caller fails clearly, and the sudoers line, which has `--within *`, does not change. The dispatcher refuses (64) a call whose row is marked
when the approved value is `plain`, as it refuses one above the approved rating.

**Built (`src/text_rule.rs`, used by `Answer` for every record of every verb and for the closing record):** the record is rewritten
token by token, so the members keep their order; keys and values, at any depth. The bound is in bytes of escaped text (`escape_bytes_clipped` counts characters; the bound is made one of bytes by asking
for fewer characters until the text fits); `clipped` gives the length of the whole string in bytes and is keyed by the innermost member name. A member of a tool's record named `escaped` or `clipped` is the tool's claim: it
is kept as `tool_escaped` / `tool_clipped` so that the two names are the dispatcher's alone. The closing record has the dispatcher's own `escaped_records` and `clipped_records` (records before it, counted for every record the verb wrote, also those the cap dropped);
a `prover` trailer also has the tool's own numbers (`tool_escaped_records`, `tool_clipped_records`) when its object gave them, and `tool_missed: true` when the dispatcher had to escape or cut something the tool did not. A tool's text that the tool already
escaped is escaped again at its backslashes (`\\u{202e}` shows as `\\\\u{202e}`): the rule does not trust a string to be escaped. `test read`'s `text` has the row's limit of 16384 bytes. An unreadable record is not passed on and fails the call (`unreadable-record`).

**Every string the dispatcher passes on is escaped** (`p_ermit::text::escape`: a refused character becomes visible literal text,
a backslash is escaped, never dropped), at any depth, for every verb, whatever the tool did. A record with an escaped string has
`"escaped": true`; the trailer counts such records by the dispatcher's own count, and gives the tool's `escaped_records` too when they differ. Each string field is clipped at **1024 bytes of escaped
output** with `"clipped": {"<field>": <full length in bytes>}` on its record (a second, tighter bound than `prover`'s own; a field a row declares as content, such as
the bytes `test read` returns, has the row's own limit and is data in a field, never spliced into anything). So a worst-case thread record is about 3 KB and **about 340 of them still
fill the 1 MiB answer**: on a host with a process built to do that the answer is truncated, its trailer has the true counts, and that is the bound, not a fault.

**The double escape (decided: it stays for stage 1).** The dispatcher trusts no tool: it does not recognise a tool's own escape form as already clean (a dispatcher that did would be a
parser of untrusted input with a reason to let things through). So **what an agent sees** of a character the tool already escaped is its form with the backslash doubled: a thread name that `prover` wrote as `\u{202e}` arrives
as `\\u{202e}`. **Reversing takes two steps**: `p_ermit::text::unescape` once for the dispatcher's layer, then again for the tool's. **The two counts differ by construction**: the trailer's `escaped_records` (and `clipped_records`) is the dispatcher's own, of the records in which *it* found
something the rule refuses; the `tool_escaped_records` and `tool_clipped_records` are the tool's claim, of what *it* escaped or cut. A tool that did its work leaves the dispatcher nothing to escape (its count is 0 and the tool's is not), and
`tool_missed: true` says the dispatcher had to escape or cut something the tool did not. If the doubling hurts in use, the way to revisit it is a **row-declared field type that the dispatcher validates strictly**, not a general "looks escaped already".

**What the dispatcher does not check:** that the action and parameters are the approved ones; it checks the rating (it re-rates a call's paths where it opens
the files), the deadline, the call identifier and, with the above, `host_text`. That is accepted (`doc/approvals.md`, the trust table).

The first table (`src/main.rs`); the ratings are proposals:

| Verb | Runs | Exposure | Damage | Disruption |
|---|---|---|---|---|
| `sys kit` | `probe` itself | `open` | `none` | `none` |
| `rt irq` | `prover irq` | `open` | `none` | `none` |
| `rt procs` | `prover procs` | `internal` | `none` | `none` |
| `rt jitter` | `prover probe jitter` | `open` | `none` | `brief` |
| `run command` | the command named | `secret` | `lasting` | `outage` |

`rt jitter` is why there is a third scale: it loads a realtime host and
reveals and destroys nothing. Rated `brief`, it is asked about by default,
which is what arming did in `diag-tools`; a person can make it automatic for
one agent by raising that delegation's ceiling for disruption, and for
nothing else.

## What the service does with a call

1. It checks that the call names this host and this service, has not ended,
   and names a verb of the table with arguments the verb accepts. Otherwise
   it answers the agent with a refusal and asks nobody.
2. It rates the call and signs a request with its own key: the call's bytes
   as received, and the rating (`doc/approval-formats.md`).
3. It sends the request to the broker (in stage 1: to the pledge on the same
   machine) and waits until the deadline.
4. Before it runs the verb it checks, and it runs nothing if one fails:
   - the approval is a valid signature over exactly this request;
   - by the person the call's delegation names;
   - with that person's confirmed approval key if the request is rated at
     the top of any scale;
   - the call's deadline has not passed, and nothing was run for this call's
     identifier before;
   - the clearance is a valid signature over this request, by the key the
     site CA certified as `broker`, and not older than 60 seconds (not in
     stage 1), **and it names the approval this service holds**: the clearance's
     `approval` is the hash of that approval's bytes (p-act's `verify_clearance`
     takes the approval); a clearance for another approval is no clearance.
5. It runs the dispatcher and returns its output to the agent.

At the deadline without an approval it answers the agent's call with
"expired". A refusal or a decline it passes on as that.

All signatures are checked with `ssh-keygen -Y verify`. Used identifiers are
kept on disk until their call's deadline, so that a restart does not forget
them.

## Order of work

1. The dispatcher with the verbs p-rover already has, and the catalogue.
2. `probe serve` on one machine: requests to a local pledge, the checks
   above. Stage 1 of `doc/approvals.md`.
3. The broker in between: stage 2.
4. Verbs from the other tools as they exist.
5. `run command`, and the verbs `diag-tools` has and this workspace does
   not.

## Open, each with a proposal

- **The name.** `probe` collides in meaning twice. *Proposal:* keep it until
  stage 1 runs, then decide with the thing in hand.
- **How an agent reaches the service.** Decided: MCP over HTTP on a port
  the sandbox may reach; the call and its signature in the tool call's
  `_meta`, the tool's arguments equal to the signed call; an agent learns of
  a "no" only a coarse class (`doc/approvals.md`, section 10). The details
  are a proposal of their own.
- **The rule for rating a call lower by its parameters.** Decided: data in
  the verb's row. The service rates a call; the dispatcher, which is where
  the file is opened, rates it again itself and refuses if its rating is
  above the approved one, which the service passes as `--within`. That flag
  can only restrict. Nothing is rated lower under a directory that anyone
  but its owner or root can write to (`doc/approvals.md`, R4). The service's
  account, through the sudo rule for `probe --within`, can run every verb:
  taking over that account is taking over the service, which the design
  trusts anyway.
- The vocabulary shared with p-ledge and p-age (ratings, the call, the
  request, their signatures) is the crate `p-act`.
- **Narrowing by noun.** `diag-tools` could limit an identity to some nouns;
  R10 has no successor for that. *Proposal:* not now; a binding could later
  name groups per noun.
- **The verbs about a site** that `diag-tools` has. *Proposal:* a second
  service on the host that has that view, with the same dispatcher; not part
  of a host's table.
