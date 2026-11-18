# Approvals: what fundament's site model would say

**A second writing.** The first copy of this note and its report were lost
with a scratchpad. This one is written again on 2026-11-18 from the same
session's text, not rebuilt from the repository, so points 1 to 8 are the
first writing's. It differs in four ways: the issuer is decided, so the
always-on variant is kept only as a short record; the decided points are
marked decided; memberships on directory sites are open again with the
owner; the report is the last section of this file. Nothing in fundament
was read again for this writing: every statement about fundament is as of
its `main` checkout on 2026-11-11.

**Where this would belong in fundament.** That repository's rules name no
home for a proposal: its `CLAUDE.md` says "No design note, no numbered
decision, no review per unit" and "an entity or field is added when a ported
role or a site's inventory needs it, never designed ahead". `doc/model/` is
the reference of what the loader does. The page this would become once built
is `doc/model/approvals.md`, linked from the theme table of
`doc/model/index.md`, its fields in `model/README.md`. Placed under
`doc/model/` unbuilt, it would be the first page there that describes
nothing the loader does. See C1.

Status: a proposal. Nothing is implemented. Terms of the approval system are
those of [`approvals.md`](approvals.md) section 1 (an "agent" is an AI
agent; a "grant" is only the model's sudo rule; the "issuer" is whoever
holds the site CA's key); everything else is fundament's. Paths without a
prefix below are paths in the fundament repository.

What the approval system takes from a site: persons with `enabled` and four
keys each; which groups may use which service on which host; who is in which
group, read where the site keeps it; hosts with their host keys; one key,
the site CA's, that certifies persons' approval keys and the broker's and
signs the list of hosts' keys. `access` and grants play no part (R10).

| Addition | Where | Kind |
|---|---|---|
| `approval_keys` on a person row | `persons.yml` | a field |
| `approval-broker`, with the site CA's slot | product `service-types.yml` | a type with a flag |
| `agents: true`; the first type that carries it | product `service-types.yml` | a flag, a type |
| `groups` on a binding of such a type | `services.yml` `params` | a typed parameter, required |
| `approval-<host>-<service>`, `approval-sync` | derived flows | two rows of the table |
| `approval_view(site)` and smaller queries | a module `approvals.py` | queries |
| a signing step in the converge | `fundament.core` | mechanism, not model |

No new top-level file and no new kind of entity. In the YAML below, type
names, unit names, ports and program names are placeholders: the software
defines its own.

**Decided, open.**

| | State |
|---|---|
| the issuer is the operator at a converge; 90-day certificates, renewed at a converge once fewer than 60 days remain; no always-on issuer | decided (J1) |
| which groups may use a service: a required `groups` parameter on the binding | decided |
| an agent's certificate: the person its only principal, groups in the extension `groups@procession` | decided; nothing in the model follows from it but the login grammar of point 1 |
| a service's key certified by its host's key, not by the site CA | decided by the owner on 2026-11-18 (J8). Where the text below still calls it open, it is not |
| memberships on a directory site come from the directory, through the sync job beside the broker | decided by the owner on 2026-11-18 (C2). Where the text below still calls it open, it is not |
| whether the first sandboxes separate model and signer | open with the owner; not a model question, see the end of [Open](#open-for-the-owner) |

## 1. A person's approval keys

A person row gains one optional field. The four purposes are the keys of a
mapping, each row the shape a `keys` row has today
(`model/README.md#personsyml`: `[{key, verified_on?}]`):

```yaml
# persons.yml
alice:
  given: Alice
  family: Example
  profile: staff
  keys:
    - {key: "ssh-ed25519 AAAAC3... alice@laptop", verified_on: 2026-10-02}
  approval_keys:
    confirmed:  {key: "ecdsa-sha2-nistp256 AAAAE2...", verified_on: 2026-11-10}
    automatic:  {key: "ecdsa-sha2-nistp256 AAAAE2...", verified_on: 2026-11-10}
    delegation: {key: "ecdsa-sha2-nistp256 AAAAE2...", verified_on: 2026-11-10}
    connection: {key: "ecdsa-sha2-nistp256 AAAAE2...", verified_on: 2026-11-10}
```

Why a second field and not four more `keys` rows with a purpose: `keys` is
"the whole attribute, set, never appended" (`doc/model/people.md`, Persons),
and every reader of it writes a login path: `local_users`, `root_keys`,
`estate_persons`, an account's `pubkeys_from_group`, the directory's key
attribute. A purpose on a `keys` row would make each of those readers
remember to filter. A field none of them reads cannot reach an
`authorized_keys` file; that is the argument `parked` makes for leaving the
derived host sets (`doc/model/inventory.md`, Parked hosts).

Why a mapping and not a list: the purposes are a closed vocabulary of four,
each exactly once. A mapping says that in its shape.

Replacing after a lost machine is one edit: the block is replaced, four rows
and their dates.

**Loader checks** (in `load_identity.py`, with the person row; cross-row
checks in the identity stage):

- the field is a mapping of exactly `confirmed`, `automatic`, `delegation`,
  `connection`; a partial set is refused;
- each row is `{key, verified_on?}`; `key` full-matches
  `load_identity.SSH_KEY` and its type is `ssh-ed25519` or
  `ecdsa-sha2-nistp256`, the two the approval system takes
  ([`approval-formats.md`](approval-formats.md) 3.1). `SSH_KEY` alone admits
  RSA and `sk-` types, which are fine for a login and refused here by name;
  `verified_on` is a calendar date;
- **the four keys of one person are four different keys**, compared on type
  and blob (adopted by the designer). A service tells a confirmed approval
  from an automatic one only by the name in the certificate; one key under
  both names would make every automatic signature verify as confirmed;
- no approval key, on type and blob, is another person's approval key, a
  `keys` row of any person, an account's `pubkey`, or a public half the
  loader holds (`Site.automation_public`, `account_public`, `cluster_keys`,
  `host_key_public`; `loader.py`). Disabled persons count: their rows are in
  the file.

One test holds the separation: no query that returns login keys returns an
approval key of the fixture.

**Queries.** `approval_keys(site, login)`: the four rows or `None`.
`approval_signers(site)`: per enabled person with the field, the login and
the two approval keys, what the issuer certifies.

**A person's name** in a certificate is the login. `_check.LOGIN`
(`[a-z_][a-z0-9_-]{0,31}`, `_check.py`) lies inside what
`approval-formats.md` 3.1 allows for the one principal of an agent's
certificate (`[A-Za-z0-9._-]+`, at most 64) and holds no `:`. The groups in
`groups@procession` are identity group names, slugs, which hold no comma.

**A second approving device** would change the certificate names first
(`approvals.md` section 9); this shape holds one set per person until then.

**Cost without approvals.** None: the field is optional. A person with the
field on a site that binds no broker loads and is inert, so keys can be
entered before the broker exists.

## 2. The site CA and the issuer

**The model has no SSH certificate authority today.** No role sets
`TrustedUserCAKeys`, no slot holds a CA key, and the binding value
`tls: internal-ca` (`entities.TLS_MODES`) has no reader in `bindings.py` or
`edge.py`. The certificate authorities a site can have are the directory's
(`public/realm-ca.pem`, issuing through `ipa_cert` on the directory host,
`doc/identity.md`) and an external ACME one. So "a site that already has a
realm CA or a user CA" reads, in the model: a realm CA on a directory site,
nothing on a local site, never a user CA.

**Another key, always.** The realm CA is an X.509 key inside the directory's
own CA; it never leaves that host and cannot make an SSH certificate. Were a
site to run an SSH user CA through a role of its own, that key must not be
this one either: sshd knows no namespaces, so one key trusted for logins and
for approvals keeps the two apart only by convention. The model's rule for
the same situation is "one ref, one contract" (`doc/model/secrets.md`,
Derived refs).

**What the issuer signs:**

| Signed | Name or namespace | From the model |
|---|---|---|
| each enabled person's two approval keys | `<login>:confirmed`, `<login>:automatic` | `approval_signers(site)` |
| the broker's key | `broker` | the public half of `service/<broker>/signing-key` (point 4) |
| the list of hosts' keys | namespace `hosts-v1@procession`, by the CA key itself | `approval_hosts(site)` (point 6) |

### The issuer is the operator, at a converge (decided)

No host holds the key.

```yaml
# product service-types.yml, on the broker's type (point 4)
approval-broker:
  secrets:
    # Services and persons' machines trust the public half: a replace in one
    # step leaves approvals nobody accepts, hence pinned, as the automation key.
    - {ns: site, key: approval-ca, kind: blob, gate: generate, generator: ssh-key,
       pinned: true}
```

- **Where the key lives.** `site/approval-ca`, in the store only. Its public
  half is the committed site file `public/site/approval-ca.pub` (the
  store's pair mechanism, `doc/secret-store/index.md`, Public halves): the
  trust anchor an administrator hands a person's machine at enrolment, and
  the line the bindings of points 4 and 5 emit.
- **Never on the broker's host.** A type's `ns: site` slot is in no host's
  lookup scope (`host_slots`: "No other `site/` ... ref",
  `doc/model/secrets.md`), so a binding for the broker's host that named it
  is refused at load as a `Lookup` outside the host's slots.
- **Which program signs, where, when.** The converge's own process on the
  controller, which already holds the store and reads the automation key in
  memory (`doc/converge/index.md`, The agent). It signs when the broker's
  host is a target of the run, and delivers certificates and the hosts list
  to that host as files. The key is never a role input and never a task
  argument.
- **Validity.** 90 days. A certificate is renewed at any converge of the
  broker's host once fewer than 60 days remain, or when the row's key is no
  longer the one certified, or when none exists. How long the present one
  has left is read from what the broker's host holds. A broker that lied
  about it could only prevent a renewal, and it can refuse everything
  anyway.
- **The alert.** The broker's type ships a rule pack over the days left on
  the certificates its host holds, written by a collector there (an
  `observability` block, `doc/model/operations.md`), the threshold a pack
  parameter.
- **What it needs that the product does not have:** a controller-side step
  that signs inside the runner's process. Every value a role gets from the
  store today is a `Lookup` in a host's scope; this one must not be. It is
  a small piece of `fundament.core`, and it is new mechanism, not model.
  The certificates can be built with `cryptography`, which the store uses
  for every key (`doc/secret-store/index.md`, Generators) and which builds
  SSH certificates. The hosts list is a product of the same converge, signed
  while the key is unlocked. It needs an SSHSIG signature by the CA key
  itself; `ssh-keygen -Y sign` takes a key from a file or an SSH agent, and
  the store's rule is that a key is never written, so the step loads the key
  into an agent of its own for that one signature, as the runner does with
  the automation key. That mechanism is this note's suggestion, not the
  designer's.
- **Loader checks.** None beyond the slot; the type is one per site
  (point 4).
- **What a site pays in liveness.** A site that does not converge the
  broker's host for 60 days loses every person's approvals at once, after an
  alert. A leaver's or a lost machine's certificates can outlive the edit by
  up to 90 days; they matter only if the broker fails as well.

**Query.** `approval_ca(site)`: the ref and the public half as the loader
read it (`None` before the first `init`; the bindings that need it return a
`Refusal`, as `bind_admin_keys` does without the automation key's half,
`doc/linux.md`).

**Not chosen: an always-on issuer on a bound host.** The first writing
proposed it while renewal was required "on a schedule". For the record, it
was `acme-issuer`'s shape (`catalogue/service-types.yml`): a type
`approval-ca` with the key as `service/<issuer>/ca-key` on its one provider,
a daily timer running `ssh-keygen`, 30-day certificates, delivery by push to
a command account on the broker's type, and a load check that its host is
neither the broker's nor a guest or node of it. It would have put a CA key
at rest on a managed host.

**Cost without approvals.** None: an unbound type derives no slot, account,
flow or unit (the active rule, `doc/model/catalogue.md`).

## 3. Names the CA refuses

1. **The issuer takes no name as input.** It is given logins, one broker key
   and hosts. It builds `<login>:confirmed` and `<login>:automatic` from a
   login and `broker` from the one field; there is no other form to ask for.
2. **The login grammar.** `_check.LOGIN` holds no `:` and no `@`, so a
   person's two names, `broker` and a service's `<service>@<host>` are
   disjoint by spelling; a person whose login is `broker` gets
   `broker:confirmed`, never `broker`. No new load refusal is needed.
3. **The verifier's lines** (`approval-formats.md` section 7). The roles of
   points 4 and 5 render two lines, so a certificate under any other name
   verifies nowhere:

   ```
   *:confirmed,*:automatic cert-authority,namespaces="approval-v1@procession" <site CA>
   broker cert-authority,namespaces="clearance-v1@procession" <site CA>
   ```

   A role renders only the lines its host verifies with, never one with
   more namespaces.

**`hosts` joins `broker`** as a name the site CA certifies for nobody. The
list of hosts' keys (point 6) is signed by the site CA's key itself, and a
pledge verifies it with a plain line, no `cert-authority`:

```
hosts namespaces="hosts-v1@procession" <site CA>
```

Where that is enforced: by 1 above, since the issuer has no input from which
the bare name `hosts` could come (a person whose login is `hosts` gets
`hosts:confirmed`; a service's name always holds `@`); and by the line
itself, which matches the CA's key and no certified key, so a certificate
named `hosts`, were one ever issued, would verify nowhere. Again no load
refusal is needed. In the signing step the two bare names are constants it
refuses to build a person's or a service's name equal to; that is its
self-test, not the model's.

## 4. The broker

```yaml
# product service-types.yml
approval-broker:
  description: The approval broker; joins services and persons' machines and evaluates the site's rule.
  tier: hub
  endpoints:
    https: {port: 443, proto: tcp}
  units: [page.service, fundament-approval-sync.timer]
  approval_broker: true
  # It authenticates its own callers: a person's machine by its connection key,
  # a service by its signed request.
  own_auth: true
  secrets:
    - {ns: site, key: approval-ca, kind: blob, gate: generate, generator: ssh-key,
       pinned: true}
    - {ns: service, key: signing-key, kind: blob, gate: generate, generator: ssh-key}
  params:
    waiting_per_agent: {type: int, default: 5}
    sync_seconds: {type: int, default: 300}
```

```yaml
# services.yml
approvals:
  type: approval-broker
  provided_by: {host: hub1}
  tls: acme
  publish:
    - {names: [approvals], via: proxy, auth: none}
```

- **Its key.** `service/<broker>/signing-key`, generated, public half
  committed; the issuer certifies that half under `broker`. A generated slot
  and not a key made on the host, because the issuer needs the public half
  and the model never reads a host.
- **One per site.** At most one service of a type flagged `approval_broker`,
  one host provider (as `idp`, `model/README.md`, The identity provider).
- **Reach from service hosts** derives: `approval-<host>-<service>`, from
  each provider of a type flagged `agents` to the broker's endpoint, a row
  of the derived-flow table (`doc/model/policy.md`), like `oidc-<service>`.
- **Reach from persons' machines** is declared by the site, as a flow or a
  publication: those machines are no model hosts, and from where they come
  is a site value with no default, as `egress` is.
- **TLS** is the binding's `tls`, the site's choice: the requirement is "a
  certificate pledge and services can verify". The model adds no check. A
  pledge and a service so hold two anchors of different kinds: the site CA's
  public half for who signed what, and the TLS root or a pinned certificate
  only for reaching the broker. The first is the model's (point 2); the
  second follows from the binding's `tls` like any service's.
- **Tier `hub`**, and `hubs_of` (`doc/model/inventory.md`, Hubs) gains the
  reason `approvals`: the broker for every host that provides a type flagged
  `agents`.

**What it is given from the site project**, when its host is converged. One
derivation, `approval_view(site)`, pure and byte-stable;
`bind_approval_broker` hands it to the role, which writes it in the form
`page load` takes and loads it when it changed:

| Part | From | Notes |
|---|---|---|
| `persons`: login -> `{enabled, keys}` | `persons.yml` | every row; the four keys only while enabled |
| `services`: type -> host -> groups | bindings of types flagged `agents` | point 5; keyed by type and host, since that is the name a call carries |
| `hosts`: name -> host key | the providers of those services | `public/host/<h>/ssh-host-key.pub`, which the loader reads already for every converged host (`Site.host_key_public`, `loader.py`) |
| `groups`: name -> `{description}` | `identity.yml` `groups` | the groups some binding names; for point 6 |
| `members`: group -> logins | `persons.yml` rows' `groups` | **on a local site only**; on a directory site the part is absent |
| `ca`, `settings` | the site CA's public half; the binding's params | |

`access`, grants and host classes are not in it: R10 reads none of them. A
host whose public half the store has not written is left out of `hosts` and
is a finding, as a cluster member without its half is (`doc/linux.md`,
admin_keys).

**Who is in which group** (open with the owner, C2). The model's rule is
that a membership has one home per site: the person row on a local site, the
directory on a directory site, where `groups` on a row is refused
(`doc/model/people.md`, Persons). The view follows it exactly as
`vpn_identities` does: the members on a local site, nothing on a directory
site, "where the converge expands it from the directory". The designer's
answer, which this note takes as its proposal: a job expands it instead of
the converge, a kit program beside the broker on a timer (`sync_seconds`,
300 proposed), which reads the members of the groups the view names from the
directory and writes them in the same form. The broker does not know which
of the two wrote the part. What the job needs from the model on a directory
site is what the IdP's federation has (`doc/model/idp.md`,
`catalogue/service-types.yml` `idp`):

- a read-only bind account contributed by the type
  (`accounts: {approval-sync: {kind: bind, auth: password, rbac_role:
  read-only}}`), with its password slot;
- the realm CA (`realm_ca: {restart: [...]}` on the type, so `ca_trust`
  serves the host where it is no realm member);
- a derived flow `approval-sync`, the broker's host to the directory's
  `ldaps` endpoint, as `idp-federation`;
- the directory's containers, from the `directory` block, as the IdP reads
  them.

One gap (J9): a type's `accounts` block is active with the type, and a bind
account means nothing on a local site. The `idp` type never meets the case
because it refuses a local site. Here the account, the realm CA flag, the
flow and the timer must exist on a directory site only; the model has that
condition for slot rows (`when: {backend: directory}`, `catalogue/slots.yml`)
and not for an `accounts` block.

**Loader checks.** One per site; every group a binding names exists; on a
local site every such group has a `gid`, as any group a person names does
already.

**Cost without approvals.** None; the type is unbound.

## 5. A service that offers actions to agents

A type says it with a flag, and the site says whose agents may use it on the
binding (decided: the binding's `groups` is the one home):

```yaml
# product service-types.yml
probe:
  description: A host's diagnostics as rated verbs, offered to agents; acts only on a person's approval.
  tier: client
  endpoints:
    mcp: {port: 8443, proto: tcp}
  units: [probe.service, fundament-approval-cert.timer]
  agents: true
  params:
    # Whose agents may use it. No default: a safety-relevant attribute is
    # declared, never defaulted, as syslog's transport is.
    groups: {type: list}
```

```yaml
# services.yml
probe-rt:
  type: probe
  provided_by: {class: realtime}
  params:
    groups: [rt-operators]
probe-hv:
  type: probe
  provided_by: {class: hypervisor}
  params:
    groups: [admins]
```

**Why on the binding.** A catalogue `grants` or `command_accounts` entry
names nobody of the site: a product grant names an `account` of its own
entry, and a command account says `from: site` and leaves the callers to
`policy.yml` (`doc/model/people.md`, Command accounts). The product cannot
know a site's group names. The site's half is a typed parameter, as
`remote-console` takes `admin_groups` (`catalogue/service-types.yml`). Two
bindings of one type name different groups for different hosts, which is
"which groups may use which service on which host". Any group passes, role
or entitlement.

**The name.** `<service>` in `<service>@<host>` and in a call is the type's
name, not the binding's: `probe` on every host, whatever the site called its
bindings. So a host provides at most one service of a type flagged `agents`,
refused at load otherwise, and such a type's name full-matches
`[a-z][a-z0-9-]*` (a model slug may start with a digit; the format may not),
checked when the catalogue loads. `<host>` is the model's host name, a slug,
inside the format's `[A-Za-z0-9._-]+`.

**The persons' rule is not derived from `groups`.**
[`crates/p-robe/SPEC.md`](../crates/p-robe/SPEC.md) says the sudo rule by
which a person calls the dispatcher "has nothing to do with agents". It
stays what it is today, a site grant in `identity.yml`
(`doc/observability.md`: "The sudo rule for people (step 9) is the site's").
Two facts, two homes.

**On each provider**, by a role bound through `bind_agent_service`:

| What | How |
|---|---|
| the program | a release artefact named by role options with its checksum, as `diag_wheel` and `diag_wheel_sha256` are (`doc/observability.md`); empty: nothing installed |
| its account | a system user the role creates; see C5 |
| its signing key | made on the host by the role when absent, Ed25519, readable by the account only. No slot: nobody off the host needs its public half, and a reinstalled host makes a new one and certifies it |
| its certificate | a kit program on a timer, as root: the host's SSH host key signs the service's public key under `<type>@<host>`, valid 30 days, reissued after 20 or when the key changed. The roll-out installs the timer; renewal needs no converge |
| the allowed-signers file | the two lines of point 3, from the site CA's public half; a `Refusal` while the half is absent |
| the dispatcher's rule for the account | a local sudoers file checked with `visudo -cf`, as `diag` writes its own; see C5 |

**Which host key, and where a wrong one is refused:**

- **The type.** A host needs an Ed25519 or ECDSA P-256 host key to run a
  service. For a managed host the model's key is the `ssh-host-key` slot,
  generated by `ssh-key`, whose default is Ed25519 and whose slot row sets
  no `type` (`catalogue/slots.yml`); the store's import check holds an
  imported value to the slot's type (`doc/secret-store/index.md`, The pair
  check). So the key the site holds is Ed25519 by construction. The loader
  still checks the half it read (`Site.host_key_public`) for each provider
  of a type flagged `agents`: any other type is a load problem naming the
  host. An RSA key can thus only be a live key the site does not hold, which
  the next check refuses.
- **The live key.** "An adopted host keeps its own key until host-key
  delivery installs the generated one" (`doc/converge/index.md`, Host keys).
  The role compares the host's live key of that type with the bound half and
  fails by name when they differ or the key is absent; the timer's program
  makes the same comparison before every signature. Nothing is certified
  with a key the site does not hold.

**Loader checks.** `groups` non-empty, every name an identity group; at most
one service of the type per host; the type's name in the format; a provider
is a converged host with a host-key slot and, where its half is present, a
half of an admitted type; a type flagged `agents` bound on a site without a
broker is refused, since its requests could go nowhere.

**Queries.** `agent_services(site)`: per type and host the binding and its
groups. `agent_services_on(site, host)`. `approval_hosts(site)`: the
providers with their public halves.

**Agent to service.** Where an agent's sandbox runs is no model fact. The
site declares the flow to the `mcp` endpoint.

**If the site CA certified service keys instead of the host key** (open with
the owner, J8). The text above is correct for the host-key variant. With the
other:

- the service's key becomes a generated host slot of the type
  (`{ns: host, key: probe-signing-key, generator: ssh-key}`), because the
  issuer needs its public half and the model never reads a host;
- the issuer signs a third name form, `<type>@<host>`, still built from
  model names only (point 3 holds; the verifiers gain a line for it);
- the host timer, the host-key type check, the live-key comparison,
  `approval_hosts`, the `hosts` part of the view, the signed list of point 6
  and the name `hosts` all go;
- with the operator as issuer, a service's certificate then renews only at a
  converge, like a person's, with the same 60-day cliff for every service of
  the site at once, and a new host cannot serve before a converge of the
  broker's host has run.

**Cost without approvals.** None; the flag is on unbound types.

## 6. What a person's machine receives

Through the broker, which carries and cannot alter what the site CA signed:

- **Renewed certificates.** Public data, in no slot; from the converge to
  the broker's host as files.
- **The list of hosts' keys**, signed by the site CA's key itself in the
  namespace `hosts-v1@procession` (point 3). What the model gives the issuer
  for it is `approval_hosts(site)`: for each provider of a type flagged
  `agents`, the model's host name and the public half of its `ssh-host-key`
  slot as the loader read it, sorted, hosts without a half left out (and a
  finding). The list changes only with a commit: a new provider, a
  reinstalled host's new half. It is a product of the converge, signed while
  the key is unlocked. A list does not expire: a pledge takes one only if
  its `at` is later than that of the list it holds and keeps the newest
  (`approval-formats.md` 6.1), so the model owes no cadence. A host removed
  from the site stays in a pledge's list until the next one; harmless, since
  it has left the broker's view with the same converge and the broker passes
  on nothing from a host it does not know. All of this stands under J8: if
  the site CA certifies service keys, there is no list.
- **Group names and descriptions**: `groups` of the view. A group's
  `description` is optional in the model; one without gives its name alone.
  Which groups are a person's comes from `members` or the sync job.
- **The trust anchor** is not received this way: the committed public half
  of the site CA's key is what an administrator hands over.

## 7. Disabling and leaving

One edit, the one the model already requires: `enabled: false` with `left`
(`doc/model/people.md`: `left` is set exactly when `enabled` is false). At
the next load:

| Derivation | Effect |
|---|---|
| `approval_signers` | the person is not listed: nothing is renewed for the two names |
| `approval_view` `persons` | the row stays with `enabled: false` and without keys: no clearance, no sign-in |
| `approval_view` `members` (local site) | the person is in no group |
| `local_users`, `root_keys`, person slots | as today |

**The order**, for a leaver (as `approvals.md` section 10 has it):

1. An administrator blocks the person at the broker (`page block`). This is
   what stops someone at once; it is not model data.
2. The edit, committed.
3. A limited converge of the broker's host
   (`fundament converge --limit <broker's host>`). Tier `hub` converges
   last (`doc/model/roles.md`, Tiers), so a whole-site run that stops in an
   earlier tier has not told the broker; the limited run first makes "stops
   with the next roll-out" hold whatever else fails.
4. The rest of the site.
5. What remains: certificates on the person's machine, valid for up to 90
   days. They matter only if the broker fails as well. On a directory site
   the memberships go with the directory's own offboarding, within one sync
   interval.
6. `retire` later, as for any person. `retired_uids` keeps the login from
   being handed out again (`doc/model/people.md`, Retired ids), so a
   leftover `<login>:confirmed` certificate can never name a later person.

The model has a shape for an offboarding step a service type owns, a
`deliveries` block with `on: [offboard]` (`doc/model/people.md`,
Deliveries). Step 1 could be the broker type's delivery. Not proposed now
(J7).

A returning person is enabled with `left` cleared; the block is entered
anew.

**A lost machine** is the block replaced (point 1), after the block at the
broker. The next converge of the broker's host certifies the new keys at
once. The model keeps no list of ended keys.

## 8. diag-tools

Until `probe` has replaced it, nothing of it changes, and the two share
nothing. Today's wiring, by file:

| Piece | Where |
|---|---|
| the command account `diag-agent`, `from: site`, a year's expiry | class `managed`, `catalogue/classes.yml`; `entities.DIAG_AGENT` |
| its callers | the site's `policy.yml` `command_callers` |
| the caller flow `command-diag-agent-<host>` | derived (`doc/model/policy.md`) |
| the shared key `account/diag-agent/ssh-key` and its public half | `catalogue/slots.yml` `command-account`; `Site.account_public` |
| identities narrowed to nouns | `observability.yml` `diag.identities` |
| nouns | catalogue `observability` blocks' `verbs`; `diag_nouns` (`doc/model/operations.md`) |
| the role and its inputs | profile `observability` (`catalogue/profiles.yml`), predicate `diag_host`, `bind_diag` in `bindings.py` (`diag_account`, `diag_key`, `diag_from`, `diag_expiry_days`, `diag_nouns`, `diag_identities`) |
| the sudo rule for people | the site's, by hand (`doc/observability.md`, diag) |

**Unnecessary once `probe` has replaced it** (and then deleted, not kept
behind a flag: "migration is deletion", `.claude/rules/house-style.md`):

- the `diag-agent` command account and `entities.DIAG_AGENT`; with it the
  account's place in `pubkey_only`, which falls out by derivation;
- a site's `command_callers` entry for it (a key naming no account is
  refused, so the site drops it with the release that drops the account);
- the derived caller flows to every managed host's sshd;
- the slot and its public half (the store reports the value as an orphan);
- `diag-agent` as a diag identity;
- the role's key line, its expiry, the arming window and the inputs
  `diag_account`, `diag_key`, `diag_from`, `diag_expiry_days`.

**What stays:**

- the command-account mechanism and `command_callers`: `log-pull`,
  `anchor-sync` and the certificate push use it;
- `admin-sources` and the controller's bound;
- a person's call of the dispatcher by sudo, by a site grant;
- catalogue `verbs`, `diag_nouns` and the per-identity narrowing, for as
  long as the Python dispatcher runs anywhere. R10 has no narrowing by noun;
  the designer's answer is "not now; a binding could later name groups per
  noun" (`crates/p-robe/SPEC.md`). A site that narrows one person to some
  nouns today loses that with the replacement;
- the verbs about a site as a whole (`mon`, `id`), which
  `crates/p-robe/SPEC.md` leaves to a later second service. Until that
  exists `diag-tools` is not replaced on the hosts that have that view.

## Conflicts

Numbered as in the first writing.

**C1. A design note, and designing ahead. Open.** fundament has neither
("No design note"; "never designed ahead"; design points are the
orchestrator's, the operator is asked only about site facts, money and
hardware; its `CLAUDE.md`). This note is a design note, written ahead of any
role or site that needs it, and it puts design questions to the owner.
*Recommendation:* keep it here in procession until a site is about to bind
the broker; then build, and write `doc/model/approvals.md` as the reference
of what was built.

**C2. Memberships on a directory site are not model data. Open with the
owner.** `persons.yml` refuses `groups` on a directory site: "memberships
are the directory's" (`doc/model/people.md`, Persons), seeded by the people
lifecycle and changed by hand with `ipa group-add-member`
(`doc/identity.md`, What a site does by hand). The converge cannot hand the
broker what the model does not hold, and a second home in the model would
break the rule that a membership has one home per site. *Recommendation:*
the sync job of point 4, which is the model's own precedent
(`vpn_identities`: `None` on a directory site, expanded from the directory).
What the owner accepts with it: on a directory site R10's answer is partly
the directory's, as fresh as the timer, and the broker's host holds a
read-only bind credential.

**C3. "On every change, and at least hourly." Settled.** A converge is an
operator's command from a clean clone with the store unlocked by a person
(`doc/converge/index.md`); the product has no trigger and no scheduled run.
The requirement is withdrawn: nothing scheduled depends on a converge.

**C4. "TLS from the site's own certificate authority." Settled.** A local
site has none, and `internal-ca` has no reader. The requirement is now any
certificate pledge and services can verify, left to the binding's `tls`.

**C5. An account for a service, and its sudo rule. Open.** `accounts` are
`bind`, `service` and `shared`: directory users on a directory site, local
users with a site-given `uid` on a local one. A command account is a forced
command over SSH. A daemon's own system user is neither, and a catalogue
grant's `account` must be an identity account or a command account of its
own entry (`load_identity.py`, the "no account" problem). So the service's
account and the rule that lets it run the dispatcher have no home in the
model today. *Recommendation:* J6.

**C6. The command (U6) and grants. Settled as out of scope.** "As sudo
matches" is not a design (`approvals.md` section 10); stage 4, not in this
note.

## Open, for the owner

Each with a recommendation and what it rests on.

- **J1. Who the issuer is. Decided:** the operator at a converge, 90 days,
  renewed below 60, no always-on issuer. It rests on the product having no
  always-on holder of a store value (`doc/secret-store/index.md`,
  `doc/converge/index.md`). What it still needs is the signing step of
  point 2.
- **J2. Product types or site types.** A site may declare types in its own
  catalogue and run its own roles (`doc/model/catalogue.md`, Two layers;
  `doc/model/site-roles.md`); the flags, the derived flows, the person field
  and the signing step need the product either way. *Recommendation:* the
  flags, field, flows and `approval-broker` in the product; `probe` as a
  site type on the first site and a product row once a second site binds it.
  Basis: "a fact only one site has is site data" (the port workspace's
  `CLAUDE.md`).
- **J3. Type names.** `approval-broker` and `probe` are placeholders. The
  type's name is on the wire and in every service certificate, so renaming
  it later is a change for every verifier, while `crates/p-robe/SPEC.md`
  still calls `probe` a working name. *Recommendation:* settle the service's
  name before the first site binds it.
- **J4. One `verified_on` per key or one for the block.**
  *Recommendation:* per key, the `keys` row's shape
  (`model/README.md#personsyml`), so one parse serves both and a single
  replaced key carries its own date.
- **J5. Settled.** The persons' dispatcher rule is not derived from the
  binding's `groups`; it stays a site grant (point 5).
- **J6. A role-made account, or a third account kind for grants (C5).**
  *Recommendation:* role-made for the first service, as the product's other
  daemons are (the observability roles create their users in their tasks),
  and the gap named in the role's README; a third account kind when a
  second service needs it. Basis: "never designed ahead".
- **J7. Whether the leaver's block at the broker becomes a delivery.**
  *Recommendation:* not now. No people converge reads deliveries yet, and a
  profile must name every active delivery (`doc/model/people.md`, Person
  profiles), which would cost every profile of such a site a line.
- **J8. Service keys certified by the host key or by the site CA. Open.**
  What changes is at the end of point 5. For the model the site CA is less:
  no host timer, no host-key checks, no signed list, no `hosts` name. With
  the operator as issuer it costs more than it did when this was first
  weighed: every service's certificate would renew only at a converge, a
  new host could not serve before a converge of the broker's host, and a
  site that misses the 60 days loses its services as well as its persons.
  *Recommendation:* the host key, as written. Basis: a managed host's key is
  already in the store with its half in the site (`catalogue/slots.yml`,
  `Site.host_key_public`), and the host renews by itself.
- **J9. The sync job's condition** (point 4). *Recommendation:* a bind
  account contributed by a type derives on a directory site only. Basis: a
  bind account is "a directory entry that never logs in"
  (`doc/model/people.md`, Accounts), so on a local site there is nothing it
  could be; that is a smaller change than a `when` on the block.
- **Whether the first sandboxes separate model and signer. Open with the
  owner.** This note has nothing on it: it was not in the brief or in the
  documents read, and where a sandbox runs is no model fact (point 5). Not
  examined from fundament's side.

## Report

**What was read.** In fundament, its `main` checkout as of 2026-11-11,
read-only: `CLAUDE.md` and `.claude/rules/*.md`; `model/README.md`;
`doc/model/` `people.md`, `policy.md`, `catalogue.md`, `secrets.md`,
`services.md`, `index.md`, `edge.md`, `operations.md`, `inventory.md`, and
`roles.md` from the profile table on; `doc/observability.md`,
`doc/identity.md`; of `doc/converge/index.md` the commands, SSH, targets
and the operator's sections; of `doc/secret-store/index.md` refs to public
halves; of `doc/linux.md` admin_keys; the product catalogue's `classes.yml`,
`slots.yml`, `service-types.yml`; greps in `python/model/src/fundament_model`
(`_check.py`, `loader.py`, `load_identity.py`, `bindings.py`,
`secret_slots.py`, `entities.py`). `develop` differed from `main` by a few
lines in `doc/model/people.md` and `model/README.md`, not read. In
procession: `doc/approvals.md`, `doc/approval-formats.md`,
`crates/p-age/SPEC.md`, `crates/p-robe/SPEC.md` on `main`, then the diff to
`integration` at commit 47bb806; sections 6.1 and 7 of
`approval-formats.md` were not read again after the designer's answers on
the hosts list, which are taken from the orchestrator's summary.

**Verified, by reading:**

- There is no SSH certificate authority in fundament: a search of `doc/`,
  `model/`, `python/` and the collections for `TrustedUserCAKeys`,
  `cert-authority` and allowed-signers found nothing of the product's.
- `internal-ca` is in `entities.TLS_MODES` and has no hit in `bindings.py`,
  `edge.py` or `load_edge.py`.
- The loader reads `public/host/<h>/ssh-host-key.pub` for every converged
  host into `host_key_public` (`loader.py`, lines 461 to 463 then).
- `_check.LOGIN` is `[a-z_][a-z0-9_-]{0,31}`.
- A catalogue grant's `account` must be an identity account or a command
  account of its own entry (`load_identity.py`, lines 555 to 565 then).
- The observability roles create their own users (`ansible.builtin.user` in
  the tasks of `alertmanager`, `loki`, `node_exporter`, `log_pull_source`,
  `diag`).
- `bind_diag` and its outputs (`bindings.py`, line 2480 then); the
  `diag-agent` account in `classes.yml`.
- The `ssh-host-key` slot row sets no `type`; the generator's default is
  Ed25519 (`doc/secret-store/index.md`, Generators).

**Not verified:**

- Nothing was run: no load, no test, no converge, no `ssh-keygen`.
- That `ssh-keygen -Y verify` accepts, in every detail, the certificates a
  controller-side builder or a host key as issuer would make; and the two
  allowed-signers lines, which `approval-formats.md` itself says were not
  run.
- That `cryptography` in the version fundament pins builds SSH certificates
  (the builder exists from version 40; the pin was not checked).
- That loading the CA key into an agent for one SSHSIG signature works as
  the runner's agent does; it is a suggestion from the converge document's
  description.
- Whether a contributed `accounts` block with a bind account loads on a
  local site today (J9 assumes it is at least meaningless there).
- Whether a failed tier stops the tiers after it, which the leaver's order
  assumes as the worst case.
- Whether fundament's token check, which lives outside the product, admits
  the approval system's program names and namespaces in the product.
- Ports, unit names, program names and type names in the YAML are
  placeholders.
