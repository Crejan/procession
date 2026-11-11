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

Status: a skeleton. `probe catalog` prints a first table of five verbs with
their ratings; nothing runs. The name is a working name. It is not p-rover's
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
reads the host key. It runs under an account of its own, and the dispatcher
gets the privilege each verb needs through the same sudo rule a person's
call uses. It holds no rule about who may what. It does hold the ratings: they are facts about its own verbs, and
rating them is its responsibility.

## Who may call

- **An agent**, only through the service, with an approval for every call.
  An agent runs in a sandbox (`doc/approvals.md`, R2): it has no account on
  this host and cannot reach the dispatcher.
- **A person**, through the dispatcher under their own login, by a sudo rule
  the site writes for that one path, as today. No approval: the person is
  there and acts themselves. The same grant is what lets that person's agent
  ask at all.

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
  `plumber` or `preserve` and passes their JSON through.
- **Rated for the worst case** (`doc/approvals.md`, R4). The table holds
  each verb's worst rating over every parameter it accepts. For a concrete
  call the service may rate lower only by a rule that stands in the table
  beside the verb, never higher, and at the top where it cannot tell.
- **`run command`**, for agents only: one command, stated in full, run once
  without a terminal and without input, with a time limit and a cap on its
  output. Rated at the top of every scale always, so it is never approved
  automatically. It exists so that a missing verb does not become a reason
  to give an agent a login. Stage 4.

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
     stage 1).
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
- **How an agent reaches the service.** *Proposal:* MCP over HTTP on a port
  the sandbox may reach, the signed call in a header of each tool call.
- **The rule for rating a call lower by its parameters.** *Proposal:* data
  in the verb's row; see `doc/approvals.md`, section 10.
- **The vocabulary shared with p-ledge** (ratings, later the call and the
  request). Today p-robe depends on p-ledge's library for it. *Proposal:* a
  small crate of its own once the call and the request are specified, used
  by p-ledge, p-age and p-robe.
- **The verbs about a site** that `diag-tools` has. *Proposal:* a second
  service on the host that has that view, with the same dispatcher; not part
  of a host's table.
