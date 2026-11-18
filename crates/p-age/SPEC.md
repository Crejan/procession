# p-age - specification (draft)

The broker of the approval system: the one central program of a site. It
checks that a request may be put to a person, carries it to that person's
machine and the answer back, and registers delegations. Binary `page`: it
pages a person, and carries messages like a page.

The system as a whole is [`doc/approvals.md`](../../doc/approvals.md); this
document uses its terms (its section 1) and specifies only what the broker
does.

License: MIT OR Apache-2.0.

Status: step 1 of the order of work is built: the register, the two
connections over TLS (`doc/approval-connections.md`), passing a request
through with persons and hosts from a file, the queue, the clearance and the
log. Checks 0 to 3 are made; check 4 (R10), `page load`, blocking by key,
the administrator's verbs and renewals are not built. The name is a working
name.

## What it is for

- A person's machine is behind NAT and often asleep; a service is somewhere
  else. Both connect out to the broker, and it joins them.
- Whether a person may have an action carried out on a host is a site's
  rule. The broker is the one place that evaluates it, so that no service
  has to hold the rules.
- An administrator needs one place to stop a person or a delegation at
  once.

## What it must not be able to do

- **Release an action.** A service acts only on an approval signed by the
  person's machine. The broker has no key a service would accept in its
  place.
- **Say who a person is.** Persons' keys are certified by the site CA, whose
  key is not here.
- **Put a foreign request in front of a person.** pledge checks itself that
  a request is from one of its own agents.

Anything that would give the broker one of these is a defect, not a feature:
a broker that renews certificates, a service that accepts a clearance alone,
a pledge that trusts the broker's word about a delegation.

## What it is trusted for

Keeping away from a person what the site would not let them have carried
out; honouring withdrawals and blocks; being there. Taken over, it can let a
person exceed their rights (with that person's own approval), ignore an
administrator's blocks, refuse everything, and see who asks for what.

## What it does

**It proves who it is.** Its key is certified by the site CA under the name
`broker`, which no person can have. It signs every clearance with it, and
everything it tells a pledge in its own name. Its TLS certificate comes from
the site's certificate authority. A pledge or a service that cannot verify
both treats it as absent.

**Two kinds of connection**, both inbound, both TLS:

- from a person's pledge, signed in with that person's connection key. It
  stays open while the machine is awake.
- from a service, which signs each request with its own key, certified by
  its host's key; the connection itself needs no sign-in.

**For a request from a service**, in this order; the first failure is the
answer, a refusal with its reason:

0. The call's deadline has not passed and is not more than 10 minutes
   ahead. This bounds what the broker holds; it is a limit, not a trust.
1. The request is signed by a service key that a host of the site project
   certified, and host and service are the ones the call names.
2. The call is signed under a delegation that is registered, not ended, not
   withdrawn (`src/register.rs`).
3. The delegation's person is enabled in the site project and not blocked.
4. That person may have this action carried out on this host
   (`doc/approvals.md`, R10): one of the delegation's groups (read from the
   extension `groups@procession` of the agent's certificate,
   `doc/approval-formats.md`, section 3.1, and from nowhere else) is a
   group the person is in, and is among the groups that the service's
   binding names for this host. Where a group may log in (`access`) plays
   no part.
Then it passes the request to that person's pledge. If that pledge is not
connected, the broker keeps the request and passes it on when the pledge
connects; per agent it keeps as many as the site's setting allows (five by
default) and refuses further ones. Either way it
waits until the request's deadline, and no longer. An approval that comes back gets the broker's clearance (a
signature over the same request, with the time) and both go to the service.
A refusal or a decline goes back as it is. At the deadline the broker
forgets the request.

It does not check the approval. That is the service's.

**For a pledge:**

- it registers a delegation the pledge sends: the certificate, verified
  against that person's delegation key from the site project;
- it takes withdrawals from the delegation's own person;
- it sends what the pledge needs: an administrator's withdrawals and blocks
  concerning this person, renewed certificates, the names of the person's
  groups.

**For an administrator**, on the broker's host: `page block` blocks a person or
one key, `page unblock` lifts a block, `page withdraw` withdraws a delegation
and `page status` says whether the broker is degraded and what it holds. They
speak to the running broker over a socket in its state directory
(`proposals/admin-socket.md`), never to `register.json`, so that the rule for
a register that cannot be written holds for them: a restricting verb prints
"blocked and stored" or "blocked, NOT stored: <why>" and exits non-zero in the
second case; unblocking is refused while the register cannot be written.
`page delegations` (a list) is not built.

The verbs' exit codes have one meaning each; each verb's `--help` and usage
print this table:

| Code | Meaning |
|---|---|
| 0 | done (and stored, where something is stored) |
| 1 | refused (an unknown person, key or delegation; unblocking while the register cannot be written) |
| 2 | usage |
| 3 | no broker answers |
| 4 | in force but NOT stored (block, withdraw) |
| 5 | the broker is degraded (`status` only; nothing else returns it) |

The socket is `admin.sock` in the state directory (0600 set after `bind`); a
peer is served only if `p_act::peer` read its credentials and its user is the
broker's own or root (`Policy::OwnUserOrRoot`: the broker runs as the owner of
its state directory, so no list of users is needed). A peer whose credentials
cannot be read is dropped, told nothing.
Blocking a key means: no request is passed to a pledge that signed in with
it, and no approval by it is given a clearance.

**From the site**, in one format (`page load`): persons with `enabled` and
their four keys; which groups may use which service on which host; hosts
with their keys. These come from the site project when the broker's host is
converged. Who is in which group comes from where the site keeps it: the
site project on a local site, the directory on a directory site, read by a
job beside the broker on a timer (5 minutes proposed) and written in the
same format. The broker does not know what a directory is. It keeps, for
each part, where it came from and when. It holds a copy and nothing else: no
rule is made here.

## What it keeps

- The register of delegations, until each one's end. On disk it is
  `register.json` in the state directory: the file readable and writable by
  its owner only (0600, the directory 0700), with a member `v`, replaced by
  writing a new file and renaming it. The broker refuses to start on a
  register it cannot read whole, and on a missing one: a deleted file and a
  damaged file are the same doubt, and an empty register in their place
  would drop blocks without a word. The first start is explicit: `page init`
  creates the empty register and refuses if one exists.
- When the register cannot be written, what happens goes by direction. A
  change that restricts (a block, a withdrawal, forgetting a registration)
  takes effect in memory at once, always, and its caller is told that it is
  in force but not stored, with a non-zero result: the administrator's verbs
  say "blocked and stored" or "blocked, NOT stored: <why>". A change that
  permits (registering, lifting a block) is refused: nothing is permitted
  that would not survive a restart as recorded. From the first failed write
  the broker is degraded: its status output and stderr say so, it tries the
  whole write again on every later change and at least once a minute, and
  it leaves that state when a write succeeds. Degraded, it goes on serving
  with what it holds in memory. To a pledge the two cases look like this
  (`doc/approval-connections.md`, section 5): its withdrawal is answered
  `withdrawn` with `stored` false; its registration is answered
  `not-registered` with the reason `unavailable`, and the connection stays
  open.
- Blocks, until lifted.
- A log of every request: when, from which host, for which person, what
  became of it. Not the parameters of the action; those are in the person's
  record and the service's.

- Requests waiting for a pledge to connect, each until its deadline.

It keeps no request beyond its deadline. An answer, an approval included,
it holds in memory until the service has acknowledged it or the deadline has
passed, whichever is first, so that a connection lost at the last moment
does not cost the person a second dialog. Never on disk, never past the
deadline. An approval is not a secret and is of use only to the service
whose request it signs.

The register's `v`: `blocked_keys` was added with `v` still 1 and "a missing
member is empty", **this one time**, because no register exists outside tests
yet. From now on a member that is added is a new `v`, and a reader refuses a
`v` it does not know (it does).

A delegation is known in the register by the SHA-256 fingerprint of the
agent's public key (`doc/approval-formats.md`, section 3.1).

## Order of work

1. The register (done), the two connections, and passing a request through,
   with persons and hosts from a file. Stage 2 of `doc/approvals.md`.
2. `page load` from the site project, checks 3 and 4, blocking. Stage 3.
3. Renewed certificates and group names to the pledges.

## Open, each with a proposal

- **The name.** `page` unless a better one turns up.
- **Where it runs.** *Proposal:* one per site, on a host that can be reached
  from outside, as a service type in fundament's catalogue.
- **Whether `atticus-server`'s relay skeleton is a starting point.**
  *Proposal:* no. It was written for another protocol; the TLS and storage
  setup may be worth reading.
- **The interfaces**: the two connections. After the call, request and
  approval of `doc/approvals.md`.
