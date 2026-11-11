# Approvals - design (draft)

How a service learns that a person agrees to an action their agent asked for.
This document is about the whole system: several programs on several
machines. Three of them are crates of this workspace:

| Program | Crate | Part |
|---|---|---|
| `pledge` | [`p-ledge`](../crates/p-ledge/SPEC.md) | the person's end |
| `page` | [`p-age`](../crates/p-age/SPEC.md) | the broker |
| `probe` | [`p-robe`](../crates/p-robe/SPEC.md) | the first service |

Status: a design. Nothing of it is built. It fixes who does what and why. It
does not fix interfaces: message formats, field names and protocols are the
next step. Numbers are proposals (section 7). Section 10 lists what is open,
each with a proposal.

## 1. Terms

Each word below means one thing in this document and in the three crates'
specifications. Where everyday use has a second meaning, the table says which
word stands for that instead.

**Who and what**

| Term | Meaning |
|---|---|
| person | a human with a row in the site project |
| administrator | a person who maintains the site project and may block others at the broker |
| agent | an AI program a person started to act for them. Never the SSH agent: that is always written "SSH agent" |
| sandbox | where an agent runs. It gives the agent no account, no shell and no key of its person; the agent's only way to the outside is calling services |
| service | a program that can carry actions out and offers them to agents. Never a job of the operating system: that is "a job of launchd" or "a unit" |
| host | a machine a service runs on |
| target | what an action acts on: a host, a disk, a unit, a path |
| pledge | the program on the person's machine that holds their keys, asks them and signs. "The person's machine" is the machine it runs on |
| broker | the one central program of a site (`page`): it checks that a request may be put to a person, carries it there and back, registers delegations |
| site project | the fundament site repository: the source of truth for persons, groups, hosts and rules |
| site CA | the key in the site's provisioning that certifies persons' keys |

**What is said and signed**

| Term | Meaning |
|---|---|
| action | one named operation of a service, with its parameters. p-robe calls its actions verbs |
| call | an agent's signed statement: this service, this action with these parameters, under this identifier, until then |
| request | a service's signed statement of one action it was called to carry out: the call and its rating. Never a message on the SSH agent socket: that is a "signing request" |
| deadline | the moment after which a call, and the request made from it, is void: nobody may approve it, and nothing is started for it. The agent sets it in the call; there is no other time in the exchange |
| approval | pledge's signature over a request. `confirmed` if the person was asked, `automatic` if not |
| clearance | the broker's signature saying a request passed its checks |
| delegation | the certificate pledge issues for an agent's key when the person starts the agent, together with the two ceilings, which stay in pledge |
| grant | fundament's rule that a group may run named commands on hosts of named classes. Nothing else is called a grant |

**How bad, and what follows**

| Term | Meaning |
|---|---|
| exposure | the most sensitive data an action can return, at worst: `open`, `internal` or `secret` |
| damage | the worst an action can do to what exists: `none`, `recoverable` or `lasting` |
| disruption | how much an action can disturb what is running, at worst: `none`, `brief` or `outage` |
| rating | exposure, damage and disruption together, stated by the service for the concrete parameters, always as the worst case |
| ceiling | a rating in a delegation. Up to the automatic ceiling a request is signed without asking; above it and up to the ask ceiling the person is asked; above that it is refused |
| mode | what pledge does with one request: `refuse`, `ask` or `automatic`. It follows from rating and ceilings |

**Saying yes and no**

| Term | Meaning |
|---|---|
| ask | show the person a dialog |
| presence check | the key hardware requiring the person (Touch ID) for one signature |
| decline | the person says no in a dialog |
| refuse | a program says no without asking the person |
| withdraw | end a delegation before its time, by its person or an administrator |
| block | an administrator stops a person or one of their keys at the broker; or a person stops a local program in pledge |
| retire | a person ends one of their own keys |

Not used at all: "authority", "relay", "role", "kind", "shell" for a desktop
app, "revoke", "confirm" as a verb.

## 2. What it is for

- **U1** An agent wants a service to carry out an action. The person approves
  that one action on their own machine.
- **U2** An agent has actions carried out whose rating its delegation makes
  automatic. The person's machine signs them without asking and records them.
- **U3** A person withdraws a delegation; the agent can do nothing more.
- **U4** A person's machine is lost. An administrator blocks its keys and
  enters new ones in the site project.
- **U5** The person's machine or the broker cannot be reached. Nothing is
  carried out.
- **U6** Where no service offers what is needed, an agent asks for one
  command to be run on one host. The person sees the command exactly as it
  will run and approves that one execution.

Not a use case, now or later: **a login or a session for an agent.** A login
is as broad as the account it opens, and a session takes whatever is typed
into it. An agent gets actions.

Later (section 9): requests between persons, a second person's approval, an
agent proposing or extending its delegation.

## 3. Rules

**R1. Nothing is carried out for an agent without an approval from its
person's own machine.** No other party can release an action: not the
broker, not an administrator, not the agent.

**R2. An agent runs in a sandbox.** It has no account on any host, no shell,
no key of its person and no sudo rule. Services are its only way to act.
Whatever a person can do under their own login on a host (the dispatcher of
p-robe by sudo, for one) is not reachable from the sandbox. Without this
rule R1 means nothing: an agent that runs as its person needs nobody's
approval.

**R3. An agent may have carried out at most what its person may.** A
delegation names some of the person's groups and can only narrow. Nobody but
the person can issue one, and it cannot be passed on.

**R4. The rating and the ceilings decide whether the person is asked.**

Whether an action reads or writes says too little. Reading a process's
memory changes nothing and can reveal everything; deleting a build directory
destroys data that nobody misses; a measurement that loads a realtime host
reveals and destroys nothing and can still stop what runs there. So a
service rates each request on three scales, and rates the worst that can
happen:

| Exposure | The answer can contain, at worst | Examples |
|---|---|---|
| `open` | what any account on that host may see | load, uptime, the list of units |
| `internal` | how the host or the site is set up and what runs on it | configuration, logs, process arguments |
| `secret` | other people's data, credentials, memory contents | `/proc/<pid>/mem`, a home directory, a key file |

| Damage | The action can, at worst | Examples |
|---|---|---|
| `none` | change nothing | every pure query |
| `recoverable` | change or remove what can be brought back or rebuilt | clear a cache or a build directory |
| `lasting` | lose data or state for good | format a disk, delete a dataset |

| Disruption | What is running can, at worst | Examples |
|---|---|---|
| `none` | not notice | every pure query that costs little |
| `brief` | be slower, or interrupted for seconds | a measurement that loads the host, a restart of a unit that comes back |
| `outage` | be down until someone acts | stop a unit, take an interface down |

- **Rating is the service's responsibility.** It knows its actions; nobody
  else does. It rates the request with its parameters (which path is read,
  which directory is cleared), and what it cannot tell it rates at the top.
  Where a call may be rated lower than its action's worst case, the rule for
  that is data beside the action, not code: for a path, a list of prefixes,
  matched after the path is resolved, with the file then opened once and
  that same open file used, so that what was rated is what is read.
- A command (U6) is always at the top of all three.

A delegation carries two ceilings, each a rating:

| Ceiling | Proposed default | Highest a person can set |
|---|---|---|
| automatic | `open`, `none`, `none` | `internal`, `recoverable`, `brief` |
| ask | `secret`, `lasting`, `outage` | `secret`, `lasting`, `outage` |

A request at or below the automatic ceiling on every scale is `automatic`;
otherwise, at or below the ask ceiling on every scale, `ask`; otherwise
`refuse`. The top of any scale is never automatic: a service accepts an
automatic approval only for a request rated below `secret`, below `lasting`
and below `outage`.

The scales are independent. A person who lets an agent clear build
directories unasked (damage up to `recoverable`) has not thereby let it load
a host.

**R5. A call is good for one request.** A call names the service, the action
and its parameters, and carries an identifier (random, 128 bits, a UUID) and
a deadline; all of it is under the agent's signature. pledge signs for an
identifier once and then keeps it as used until the deadline, after which
the call is void anyway. A call that comes a second time gets a refusal, not
a second approval.

**R6. A request cannot say something else than the call.** A request
contains the call as the bytes the agent signed and adds only the rating;
action, parameters and deadline exist once, in the call. What pledge
compares is that the service that signed the request is the service the call
names. A request from any other is refused and recorded.

**R7. A call has a deadline, and an approval covers that one request, once,
until then.** The agent sets the deadline: how long it is prepared to wait.
There is no second time in the exchange. When the deadline passes without an
approval, the service answers the agent's call with "expired", and pledge
records the request as expired. An approval that arrives late is worthless:
the service refuses it. The deadline bounds the start of an action, not its
run time.

**R8. Only a person's own agents reach that person.** A request reaches a
dialog, or an automatic approval, only if its call is signed by an agent
whose delegation this pledge issued, not past its end and not withdrawn.
Everything else is refused without a dialog.

**R9. pledge signs only what it shows, and shows it as it is.** A dialog is
built from the request's fields and nothing else. No field is shortened or
altered for display: a request with a field that is too long, or that
contains control characters or bidirectional marks, is refused. What the
agent says about its reasons is shown as the agent's claim, apart from the
rest.

**R10. What a person may have carried out is the site project's answer**,
not a second rule set: the person (`persons.yml`, `enabled`), their groups
(`identity.yml` `groups`), where a group is admitted (`access`, by host
class), and which commands a group may run where (grants). The broker
evaluates it.

**R11. When in doubt, no.** Expired, unreachable, unverifiable, unknown: no
action.

**R12. Everything is recorded on the person's machine**: each request that
reached it, the answer (approved, declined, refused, expired), the key that
signed, the agent.

## 4. Threat model

### What is trusted, and for what

| Trusted | For | Not for |
|---|---|---|
| a service | doing what its request says and nothing else; rating honestly. A service can do what it can do, with or without a request, so nothing here can restrain it | |
| the site project and its administrators | saying who is who and who may what; entering people's keys | |
| the broker | keeping what a person may not have carried out away from them (R10); honouring withdrawals and blocks; limits; being there | releasing an action (R1); saying who a person is; saying a request is a person's own agent's (R8, which pledge checks itself) |
| the sandbox | giving an agent no way out except services (R2) | keeping the agent's key secret |
| the key hardware of a person's machine | not giving up a key; a presence check where the key demands one | |
| OpenSSH's signature tools | verifying correctly | |

Not trusted at all: agents, and the network.

The broker is trusted for a lot. What it cannot do, even taken over, is have
an action carried out that the person's machine did not sign, or put a
request in front of a person that is not from that person's agent.

### What must hold

| # | Goal |
|---|---|
| G1 | An agent does no damage by mistake or by being talked into it |
| G2 | An agent cannot be used by someone else |
| G3 | A person does no damage by mistake, and nothing beyond their rights |
| G4 | A stranger gets no access and can approve nothing |
| G5 | No person can act as another |
| G6 | Nobody can put requests in front of a person except that person's own agents |

### Threats

| Threat | Goal | What stops it | What remains |
|---|---|---|---|
| An agent asks for something harmful (a bug, an injected instruction) | G1 | R2: it can only ask. R3: only inside its delegation. R4: anything at the top of a scale needs the person; by default so does everything but a harmless query. Limits on how much it may ask (section 7) | A harmful action under a ceiling the person raised. A person who approves a plausible request. A service that rated too low |
| An agent's key is copied (the sandbox's host, a leak) | G2 | The key is short-lived and narrow. R1: every use passes the person's machine and is recorded there. The person withdraws the delegation in pledge, which stops signing for it at once | Until someone notices: whatever lies under the automatic ceiling. By default harmless queries |
| A call is captured and sent again | G1, G6 | R5: one request per call, enforced by pledge | Nothing known |
| A request says something else than the call | G1 | R6 | Nothing known; the service is trusted anyway |
| The sandbox leaks: the agent gets its person's account | G1 | Nothing in this design (trusted, above) | Everything the person can do on that host. R1 does not apply any more |
| A person approves the wrong thing, or asks for more than they may | G3 | R10 at the broker. R9: the dialog shows the request as it is | An entitled person approving a wrong but permitted action. A second person's approval is later |
| A stranger sends calls, requests or approvals | G4, G6 | An approval verifies only with a key the site CA certified for that person. R8 keeps requests away. A request verifies only with a service key that a known host certified. The broker is recognised by its certificate | Nothing known |
| A person's machine is stolen | G4 | A confirmed approval and a new delegation need a presence check. An administrator blocks its keys at the broker; no clearance, no action | Until it is blocked, and if the thief has the unlocked session: automatic approvals for agents already running |
| A person signs as another | G5 | Each key is certified for one person by the site CA; a service checks that the approval is by the person the request names; an administrator, not the person, enters keys | An administrator entering a wrong key (trusted) |
| Someone floods a person with dialogs | G6 | R8, checked by pledge itself; limits and muting (section 7), enforced by pledge; one dialog at a time | A person's own agent, up to those limits |
| The broker is taken over | G3 | R1, R6, R8 are checked by pledge and by services without it | R10 is gone: a person can have carried out what the site would not let them. Withdrawals by an administrator and blocks are gone. It can refuse everything, and sees who asks for what |
| The broker is taken over and a person's machine is stolen | G4 | The presence check for confirmed approvals | Automatic approvals, until that person's certificates run out |
| Someone on the network | all | TLS; everything that matters is signed; calls and requests are single-use and end | Delay and loss, which end in "no" |
| Malware in the person's session | G4 | Presence checks; pledge checks which program connects to its sockets | Automatic approvals. A dialog imitated to obtain a touch |
| A service lies about what it will do, or rates dishonestly | G1, G3 | Nothing (trusted) | Stated so that nobody assumes otherwise |

## 5. By what means

**Signatures.** SSHSIG, one namespace per use (call, request, approval,
clearance, connection), verified with `ssh-keygen -Y verify`. A service
needs no library.

**A person's keys**, made in the machine's key hardware. pledge prints their
public parts as one block; an administrator enters it in the site project.

| Key | Presence check | Signs |
|---|---|---|
| confirmed approval | each signature | approvals the person was asked for |
| automatic approval | none | approvals in mode `automatic` |
| delegation | each signature | an agent's certificate |
| connection | none | pledge's sign-in to the broker |

The keys an SSH client logs in with are separate again (p-ledge's
specification).

**Certificates for persons.** The site CA certifies the two approval keys
for their person and use (`<person>:confirmed`, `<person>:automatic`). A
service holds one line, the site CA's key, and tells a confirmed approval
from an automatic one by the name it verifies against. A certificate is
valid for 30 days and renewed automatically while the person is enabled in
the site project. The site CA's key is in the site's provisioning, never at
the broker: a broker that could certify keys could approve as anyone.

**A service has a key of its own, certified by its host.** The host's SSH
host key signs a certificate for the service's key, naming the service. The
service signs its requests with its own key and needs no access to the host
key, so it does not have to run as root for that. Whoever verifies a request
needs the host's public key, which the site already knows for every host and
which pledge already uses to verify hosts for logins. The certificate is
issued when the service is installed, by whoever may read the host key (the
site's provisioning, as root), and is renewed with the roll-out. A host that
is taken over has lost its services anyway, so this adds no new trust.

**The broker has a certificate too.** The site CA certifies the broker's key
under the name `broker`, which no person can have. With that key the broker
signs its clearances and everything it sends to a pledge (blocks,
withdrawals, renewed certificates, group names), and pledge and services
accept nothing as the broker's that it does not verify. The connections to
the broker are TLS with a certificate from the site's own certificate
authority, so that nobody else can stand in its place on the network. A
service and a pledge therefore hold one trust anchor for persons and broker,
the site CA's key.

**The call.** What an agent signs, with its delegated key: the host and name
of the service, the action and its parameters, an identifier (random, 128
bits), and the deadline. The service puts the call into its request
unchanged, as the bytes it received. The exact formats are in
[`approval-formats.md`](approval-formats.md).

**Delegation.** pledge creates the agent's key pair, signs the public part
into an SSH certificate with the person's delegation key (validity, and the
chosen groups as principals), registers the certificate with the broker, and
gives key and certificate to the sandbox as the person starts the agent. An
SSH certificate cannot be the issuer of another, so a service cannot verify
that chain with `ssh-keygen`; it does not have to (R1). pledge checks calls
against the delegations it issued. The broker checks them against the
person's delegation key from the site project.

**Who checks what.** Each check is made by the party that loses if it is
skipped.

| Check | Service | Broker | pledge |
|---|---|---|---|
| the call is signed under a delegation that is registered, not ended, not withdrawn | | yes | yes (its own) |
| the call names this service; its deadline has not passed and is not further away than allowed | yes | | yes |
| the call's identifier was not used before (R5) | | | yes |
| the request is signed by a service key that a known host certified, and host and service are the ones the call names | | yes | yes |
| request and call agree on action and parameters (R6) | | | yes |
| the person is enabled and not blocked; R10 | | yes | |
| limits on how much an agent asks | | | yes |
| mode from rating and ceilings (R4) | | | yes |
| the approval is over exactly this request, by the person the call's delegation names | yes | | |
| the approval's key fits the rating (R4) | yes | | |
| at the moment of acting: the deadline has not passed, and nothing was carried out for this call's identifier before | yes | | |
| the clearance is over exactly this request, fresh, and by the key the site CA certified as `broker` | yes | | |
| what arrives over the connection as the broker's is signed by that key | | | yes |

**Withdrawing.** A person withdraws in pledge, which stops signing for that
delegation at once; that alone is enough, since nothing is carried out
without pledge (R1). pledge also tells the broker, which then stops passing
requests on. An administrator withdraws or blocks at the broker; pledge
learns of it over its connection, which it holds whenever the machine is
awake, and stops as well. A service never needs a list of what was
withdrawn: without a clearance it does nothing, and the broker gives none.
The 30 days of a person's certificate are only what remains if the broker
itself fails at this.

**Checked with OpenSSH 10.2**, with keys in files: a signature by a
certified key verifies against a single CA line; the same signature is
refused for another person's name, another namespace, changed data, an
expired certificate and a revoked key; two certified keys of one person are
told apart by name; a person's key can issue a certificate for an agent's
key, and that does not verify through the site CA. A host key certifying a
service's key is that last mechanism again, with the host key in the place
of the person's. **Not checked:** any of it with keys in a Secure Enclave;
an SSH host key in the issuing role (it is an ordinary key, so expected to
work).

## 6. What runs where

| Place | Runs | Holds |
|---|---|---|
| the person's machine | pledge | the person's keys, in hardware; the ceilings of their delegations; the calls it has signed for; the record |
| the sandbox | the agent | its key and certificate |
| a host | a service | its own key, with the certificate the host key issued for it; the site CA's public key |
| the broker's host | the broker (`page`) | its key, with the certificate the site CA issued for it; its TLS certificate; requests waiting for a person, until their deadlines; persons, groups, access rules, grants, hosts with their keys and classes, persons' keys, all from the site project; the register of delegations |
| the site's provisioning | the site project, the site CA, the roll-out | the site CA's key |

```
 person's machine                         broker's host
 ┌─────────────┐      (2) TLS, outbound  ┌──────────┐
 │   pledge    │────────────────────────▶│  broker  │
 └─────────────┘                         └────▲─────┘
                                              │ (3) TLS, outbound
 sandbox                                 ┌────┴─────┐ host
 ┌─────────────┐      (1) call           │ service  │──(4)──▶ target
 │    agent    │────────────────────────▶│          │
 └─────────────┘                         └──────────┘
```

1. The agent sends a call to the service.
2. pledge holds a connection to the broker whenever the machine is awake.
   Requests arrive on it; approvals, new delegations and withdrawals leave on
   it; blocks, renewed certificates and the names of the person's groups
   arrive on it.
3. The service sends its request to the broker and receives approval and
   clearance, or a refusal.
4. The service carries the action out by its own means.

The agent and pledge are never in contact once the agent runs. The broker
never reaches a target.

### Flows

**A. Starting an agent**
1. The person picks groups and the two ceilings; a presence check.
2. pledge creates the agent's key, issues the certificate and registers it
   with the broker.
3. The person starts the agent in its sandbox with key and certificate.
   pledge keeps neither.

**B. An action**
1. The agent signs a call and sends it to the service.
2. The service checks that the call names it, rates the action for these
   parameters, and signs a request: the call and the rating. It sends the
   request to the broker.
3. The broker checks (section 5) and passes the request to the person's
   pledge, or refuses. If that pledge is not connected, the broker keeps the
   request until its deadline and passes it on as soon as the pledge
   connects.
4. pledge checks (section 5) and derives the mode:
   - `refuse`: it answers no;
   - `automatic`: it signs with the automatic approval key;
   - `ask`: it asks; if the person agrees, a presence check, and it signs
     with the confirmed approval key; if the person declines, it answers no.
   In every case it records what happened.
5. The broker adds its clearance and returns both. The service checks
   (section 5) and carries the action out.

If the deadline passes first: the service answers the call with "expired",
pledge closes the dialog and records the request as expired, the broker
forgets it. Each of the three watches the deadline itself.

**C. Withdrawing (U3)** As described in section 5.

**D. A lost machine (U4)** An administrator blocks the person's keys at the
broker, then replaces them in the site project: the person makes new keys on
the new machine, the administrator enters them, the roll-out certifies them.
Delegations of the old machine end with its delegation key.

**E. Renewal** On a schedule the site's provisioning issues fresh
certificates for every enabled person's approval keys; pledge receives them
over its connection. A disabled person gets none.

## 7. Numbers (proposals)

| What | Value | Enforced by |
|---|---|---|
| a delegation's validity | 8 hours by default, 24 at most | pledge when issuing; broker and pledge when checking |
| a call's deadline | the agent's choice; 2 minutes ahead is a sensible default, more than 10 is refused | service, pledge |
| a clearance | issued when the approval comes back; good for 60 seconds | service |
| a person's certificate, and the broker's | valid 30 days, renewed after 20 | site CA |
| a service's certificate | valid 30 days, renewed after 20 | the host key, by the site's provisioning |
| requests the broker keeps for a pledge that is not connected | until each one's deadline; per agent as many as the setting below, further ones are refused | broker |
| how long used identifiers are remembered | until the call's deadline; kept on disk across restarts | service, pledge |
| tolerated clock difference | 60 seconds | all |
| dialogs on screen | one | pledge |
| requests waiting per agent | a setting, 5 by default; further ones are refused | pledge (its own setting, per person); the broker (the site's setting) |
| declines before an agent is muted | 3 within 10 minutes; then its requests are refused without a dialog for 10 minutes and the person is told | pledge |
| a field shown in a dialog | 200 characters; a command 2000; longer is refused | pledge |
| a command's run (U6) | 60 seconds by default, 10 minutes at most; 1 MiB of output | service |
| the record on the person's machine | kept one year | pledge |
| roll-out of a change in the site project to the broker | on every change, and at least hourly | site's provisioning |

## 8. Stages

Each stage is usable by itself and is the test of the one before.

1. **One Linux machine, keys in files.** pledge in its development form
   (p-ledge, order of work, step 2), `probe` with the verbs p-rover has, an
   agent in a sandbox on the same machine. No broker, no site CA: the
   service's allowed-signers file lists the one person's two approval keys
   directly, and there is no R10 because the machine has one person. This
   proves calls, requests, approvals, ratings, deadlines and the record.
2. **The person's machine is a Mac.** Keys in the Secure Enclave, presence
   checks, dialogs. The broker (`page`) between the Mac and a Linux host,
   with its register and with hosts and persons from a file.
3. **A site.** The site CA and certificates, the roll-out from the site
   project to broker, hosts and pledge, R10 from the site's model, renewal,
   blocking.
4. **The command (U6)**, and verbs beyond p-rover's.

## 9. Later, and what the stages must not close off

- **Requests between persons** (a user asks an administrator for a password
  reset), and **a second person's approval** for an action. For these a
  request names who asks as either an agent of a person or a person, and a
  clearance names every person whose approval is needed; the stages use one
  of each form and must not assume there can be no other. R8 then gains a
  second case: a person the site's rules let ask.
- **An agent proposing its delegation, or asking for more.** The answer is a
  new delegation from the person; the agent changes nothing itself.
- **Sandboxes provided by the site**, as a program of its own.
- **A second approving device** per person, so that a closed laptop does not
  stop an agent.
- **Encryption through the broker**, so that it does not see what is asked.
- **pledge on Linux** with a FIDO2 token.

## 10. Decided, and open

Decided since the first draft, and worked in above or in the crates'
specifications:

- An agent reaches a service by MCP over HTTP, the signed call in a header
  of each tool call. The sandbox allows connections to services and nowhere
  else.
- Key and certificate get into a sandbox on another host over the SSH
  connection the person starts it through, on standard input.
- A command (U6) is matched against grants as sudo matches: its path and
  arguments against the grant's `commands`, run as the grant's `runas`. No
  grant, no request.
- There is one broker per site. It learns of hosts and their keys with the
  roll-out, like everything else. Its clearance says "passed" and nothing
  more.

Open:

- **In fundament's model**, to be agreed there: a home for a person's four
  keys; that a service type in the catalogue names the groups that may use
  it, as it names `grants` and `command_accounts` today (finer rules per
  action only when one is needed); the broker as a service type; the host
  key certifying a service's key as part of the roll-out.
- **Where exactly the lines between the levels of a scale run.** The
  examples in R4 are a start, not a definition. To be settled with the first
  real verb table.
- **Not checked** (section 5): keys in a Secure Enclave in every role this
  design gives them.
- **The interfaces.** The formats of call, request, approval and clearance
  are in [`approval-formats.md`](approval-formats.md). Next: the connections
  (agent to service, service to broker, pledge to broker).
