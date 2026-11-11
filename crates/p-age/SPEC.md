# p-age - specification (draft)

The broker of the approval system: the one central program of a site. It
checks that a request may be put to a person, carries it to that person's
machine and the answer back, and registers delegations. Binary `page`: it
pages a person, and carries messages like a page.

The system as a whole is [`doc/approvals.md`](../../doc/approvals.md); this
document uses its terms (its section 1) and specifies only what the broker
does.

License: MIT OR Apache-2.0.

Status: a skeleton. `src/register.rs` implements the register of
delegations with tests. Nothing else exists. The name is a working name.

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

1. The request is signed by a service key that a host of the site project
   certified, and host and service are the ones the call names.
2. The call is signed under a delegation that is registered, not ended, not
   withdrawn (`src/register.rs`).
3. The delegation's person is enabled in the site project and not blocked.
4. That person may have this action carried out on this host
   (`doc/approvals.md`, R10): they are in one of the delegation's groups,
   the group is admitted on the host's class, and the group may use this
   service.
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

**For an administrator**, on the broker's host: `page delegations` lists and
withdraws, `page block` blocks a person or one key and lifts a block.
Blocking a key means: no request is passed to a pledge that signed in with
it, and no approval by it is given a clearance.

**From the site project**, by the site's roll-out (`page load`): persons
with `enabled`, their four keys, their groups; the access rules by class;
which groups may use which service; hosts with their keys and classes. The
broker holds a copy and nothing else: no rule is made here.

## What it keeps

- The register of delegations, until each one's end.
- Blocks, until lifted.
- A log of every request: when, from which host, for which person, what
  became of it. Not the parameters of the action; those are in the person's
  record and the service's.

- Requests waiting for a pledge to connect, each until its deadline.

It keeps no request beyond its deadline and no approval at all.

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
