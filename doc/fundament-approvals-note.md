# Approvals: what fundament's site model would say

**Third writing, on fundament's `develop`.** The first two writings stood on
fundament's `main` as of 2026-11-11. This one, of 2026-11-19, stands on
`develop` at commit 8b6fe8f, which knows three kinds of site and has a site
CA with a signing step; both change this note. `develop` is 16 commits ahead
of `main` and other sessions are still editing it, so what is said here
about the hosted directory and the site CA may move again. What was read on
`develop` and what is still as read on `main` is in the [Report](#report).

**Where this would belong in fundament.** That repository's rules name no
home for a proposal: its `CLAUDE.md` says "No design note, no numbered
decision, no review per unit" and "an entity or field is added when a ported
role or a site's inventory needs it, never designed ahead". `doc/model/` is
the reference of what the loader does. The page this would become once built
is `doc/model/approvals.md`, linked from the theme table of
`doc/model/index.md`, its fields in `model/README.md`. Decided (C1): the
note stays here in procession until a site is about to bind the broker.

Status: a proposal. Nothing is implemented. Terms of the approval system are
those of [`approvals.md`](approvals.md) section 1 (an "agent" is an AI
agent; a "grant" is only the model's sudo rule; the "issuer" is whoever
holds the site CA's key); everything else is fundament's. Paths without a
prefix below are paths in the fundament repository.

**Three kinds of site.** `backend(site)` is derived, never declared
(`doc/model/people.md`, The backend is derived; A hosted directory;
`python/model/src/fundament_model/hosted.py`):

| Kind | When | Accounts and groups on a host | A membership's home | `enabled` lives |
|---|---|---|---|---|
| `local` | neither of the others | local users the converge writes | the person row's `groups` | `persons.yml` |
| `directory` (FreeIPA) | a service of a type with a `directory` block is active | sssd, joined to the realm | the directory; `groups` on a row refused | `persons.yml`, applied by the people lifecycle |
| `hosted-ldap` (Google Secure LDAP) | `site.yml` names a provider of type `hosted-ldap` | sssd over the provider's LDAPS, read live, one client certificate per host | the provider; `groups` on a row refused | the provider (`offboard` suspends); `persons.yml` may be empty |

The first site to bind the broker is a `hosted-ldap` one; a FreeIPA site is
to follow.

**What the approval system takes from a site.** Two inputs to the broker,
the same on every kind (point 4): the *site file*, from the model at a
converge (hosts with their keys, service bindings, the groups they name,
persons with their approval keys), and `directory.json` (who is active and
who is in which group), written by the converge on a local site and by a
job beside the broker on the other two. And one key, the site CA's, that
certifies persons' approval keys and the broker's and signs the list of
hosts' keys. `access` and grants play no part (R10).

| Addition | Where | Kind |
|---|---|---|
| `approval_keys` on a person row | `persons.yml` | a field |
| `approval-broker`, with the approvals CA's slot | product `service-types.yml` | a type with a flag |
| `agents: true`; the first type that carries it | product or site `service-types.yml` | a flag, a type |
| `groups` on a binding of such a type | `services.yml` `params` | a typed parameter, required |
| `approval-<host>-<service>` | derived flows | a row of the table |
| `approval_view(site)`, `approval_directory(site)`, smaller queries | a module `approvals.py` | queries |
| user certificates and an SSHSIG in `site_ca_sign` | `fundament.core` | an extension of what exists |

No new top-level file and no new kind of entity. In the YAML below, type
names other than `probe`, unit names, ports and program names are
placeholders: the software defines its own.

**Decided, open.**

| | State |
|---|---|
| the issuer is the operator at a converge; 90-day certificates, renewed at a converge once fewer than 60 days remain; no always-on issuer | decided (J1) |
| which groups may use a service: a required `groups` parameter on the binding | decided |
| an agent's certificate: the person its only principal, groups in the extension `groups@procession` | decided; nothing in the model follows from it but the login grammar of point 1 |
| a service's key certified by its host's key, not by the site CA | decided (J8) |
| who is active and who is in which group: `directory.json`, by the converge on a local site and by the job `page-sync` on the other two | decided (C2), as point 4 has it |
| an administrator may prolong a stale `directory.json` with `page directory extend` | decided by the owner |
| on `hosted-ldap`, an account that is only suspended and keeps its groups keeps approving until its groups are removed or it is blocked | decided: the owner accepts the limit (point 7) |
| C1, J2, J3 (the name `probe`), J4, J6, J7 | decided as recommended |
| verbs marked `host_text` are not excluded from the automatic mode | decided; not a model matter |
| whether a hosted site keeps a `persons.yml` row for those who approve | open with the owner (E, under [Open](#open-for-the-owner)) |
| J9, the sync job's bind account on a FreeIPA site | deferred until a FreeIPA site is ported |
| whether the first sandboxes separate model and signer | open with the owner; not a model question |

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
attribute, and on a hosted site the provider's `sshPublicKeys`, which
`onboard` writes "exactly as the row lists them" (`doc/identity.md`, People
on a hosted directory). A purpose on a `keys` row would make each of those
readers remember to filter. A field none of them reads cannot reach an
`authorized_keys` file or the provider's key list.

Why a mapping and not a list: the purposes are a closed vocabulary of four,
each exactly once. A mapping says that in its shape.

Replacing after a lost machine is one edit: the block is replaced, four rows
and their dates. One `verified_on` per key (decided, J4).

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
  and blob. A service tells a confirmed approval from an automatic one only
  by the name in the certificate; one key under both names would make every
  automatic signature verify as confirmed;
- no approval key, on type and blob, is another person's approval key, a
  `keys` row of any person, an account's `pubkey`, or a public half the
  loader holds (`Site.automation_public`, `account_public`, `cluster_keys`,
  `host_key_public`, the site CA's two halves; `loader.py`). Disabled
  persons count: their rows are in the file.

One test holds the separation: no query that returns login keys returns an
approval key of the fixture.

**On a hosted site** the model cannot compare an approval key with the
login keys a person holds at the provider when the row lists none: those
live at the provider. That the two lists never share a key is then a rule
for whoever enters them, not a load check.

**Queries.** `approval_keys(site, login)`: the four rows or `None`.
`approval_signers(site)`: per person with the field whom the model does not
hold disabled, the login and the two approval keys, what the issuer
certifies.

**A person's name** in a certificate, in the site file and in
`directory.json` is the login. `_check.LOGIN`
(`[a-z_][a-z0-9_-]{0,31}`, `_check.py:42`) lies inside what
`approval-formats.md` 3.1 allows (`[A-Za-z0-9._-]+`, at most 64) and holds
no `:`. On a hosted site the login is also the provider's `uid`: `onboard`
writes the POSIX account's username as the login (`doc/identity.md`). The
groups in `groups@procession` are identity group names, which on a hosted
site "name the provider's groups by their LDAP `cn`"
(`doc/model/people.md`, A hosted directory).

**A second approving device** would change the certificate names first
(`approvals.md` section 9); this shape holds one set per person until then.

**Cost without approvals.** None: the field is optional. A person with the
field on a site that binds no broker loads and is inert.

## 2. The site CA and the issuer

**What exists on `develop`.** A site with `site.yml` `site_ca: true` has two
generated site slots (`catalogue/slots.yml`, `site-ca`;
`doc/model/secrets.md`, The site CA): `site/ca/x509`, an EC P-256 CA, and
`site/ca/ssh`, an Ed25519 key whose public half `public/site/ca/ssh.pub` is
the `known_hosts` line `@cert-authority * <key>`. "No host's scope holds
either ref, so no lookup renders a CA key." The one reader is
`fundament.core.site_ca_sign` (`doc/core.md`), which signs in the controller
process with `cryptography`, returns certificates only, and is idempotent:
the target's `current` certificate is returned unchanged while it is the
CA's, for the same key and names, with more than `renew_days` left. For
`kind: ssh` it issues **host certificates only**. The earlier writings'
"the model has no SSH certificate authority" and "the signing step is new
mechanism" were true of `main` and are withdrawn.

**The approvals CA is a key of its own, in a slot beside `site/ca/ssh`.**
`site/ca/ssh` is what clients' `known_hosts` trust for *which machine this
is*. A key trusted for that must not also certify persons: sshd and
`known_hosts` know no namespaces, so one key for both keeps a host's
identity and a person's approval apart only by convention. The model's rule
for the same situation is "one ref, one contract" (`doc/model/secrets.md`,
Derived refs). Nor can it be the realm CA of a FreeIPA site, an X.509 key
that never leaves the directory host, or `site/ca/x509`.

```yaml
# product service-types.yml, on the broker's type (point 4)
approval-broker:
  secrets:
    # Services and persons' machines trust the public half: a replace in one
    # step leaves approvals nobody accepts, hence pinned, as the automation key.
    - {ns: site, key: ca/approvals, kind: blob, gate: generate, generator: ssh-key,
       pinned: true}
```

- **Where the key lives.** `site/ca/approvals`, in the store only, derived
  while the broker's type is bound (the active rule), whether or not the
  site has `site_ca`. The generator is `ssh-key`, not `ssh-ca`: the public
  half is then the bare key line an allowed-signers file takes
  (`public/site/ca/approvals.pub`), not a `known_hosts` line. That half is
  the trust anchor an administrator hands a person's machine at enrolment,
  and the line the bindings of points 4 and 5 emit.
- **Never on the broker's host.** A type's `ns: site` slot is in no host's
  lookup scope (`host_slots`, `doc/model/secrets.md`), so a binding for the
  broker's host that named it is refused at load.

**What the issuer signs:**

| Signed | Name or namespace | From the model |
|---|---|---|
| the two approval keys of each person `approval_signers` lists | `<login>:confirmed`, `<login>:automatic` | `approval_signers(site)` |
| the broker's key | `broker` | the public half of `service/<broker>/signing-key` (point 4) |
| the list of hosts' keys | namespace `hosts-v1@procession`, by the CA key itself | `approval_hosts(site)` (point 6) |

### The issuer is the operator, at a converge (decided)

No host holds the key. The signing goes through `site_ca_sign`, extended.

- **When.** When the broker's host is a target of the run. The certificates
  and the hosts list are delivered to that host as files.
- **Validity.** 90 days, renewed once fewer than 60 remain: that is
  `site_ca_sign`'s own idempotence with `renew_days: 60`, the present
  certificate read from the broker's host as `current`. A certificate is
  also issued anew when the row's key is no longer the one certified, or
  when none exists. A broker that lied about `current` could only prevent a
  renewal, and it can refuse everything anyway.
- **What `site_ca_sign` still lacks:**
  1. a kind that signs with `site/ca/approvals` and issues a *user*
     certificate with exactly one principal and a validity;
  2. issuing it with **no critical option and no extension** (everything
     cleared, as `ssh-keygen -s ... -O clear` does), because a verifier
     refuses one that has any (`approval-formats.md`, section 3.2);
  3. an SSHSIG signature by the CA key itself over the hosts list.
     `cryptography` builds certificates and has no SSHSIG;
     `ssh-keygen -Y sign` takes a key from a file or an SSH agent, and the
     store's rule is that a key is never written. So either a few lines of
     own code for the SSHSIG framing, or the key loaded into an agent of
     the step's own for that one signature, as the runner does with the
     automation key (`doc/converge/index.md`, The agent). This choice is
     this note's suggestion, not the designer's;
  4. that it is not refused on a site without `site_ca`: today it is,
     because no slot derives the CA's ref.
- **What it writes for the broker** has one layout. The certificates
  directory holds only what the broker carries to persons' machines, the
  approval-key certificates, each a file named `<login>-<purpose>-cert.pub`
  (OpenSSH's convention for a certificate file); the broker reads only
  `*-cert.pub` there and takes person, purpose and key from the
  certificate, never from the name; directory and files are owned by root
  or the broker's user with no write bit for group or others, and a
  directory that fails that is refused whole. The broker's own certificate
  is not in that directory: it is a separate file beside the broker's
  signing key, named in the broker's configuration (a `certificate` path
  next to the key's). The broker checks it at start (issuer the site CA,
  the name `broker`, validity, no critical option, no extension, and that
  it certifies the key the broker holds) and issues no clearance without a
  valid one. The site CA's public key is a file of its own (`site_ca` in
  the broker's configuration).
- **The alert.** The broker's type ships a rule pack over the days left on
  the certificates its host holds, written by a collector there (an
  `observability` block, `doc/model/operations.md`), the threshold a pack
  parameter.
- **What a site pays in liveness.** A site that does not converge the
  broker's host for 60 days loses every person's approvals at once, after
  an alert. A leaver's or a lost machine's certificates can outlive the
  change by up to 90 days; they matter only if the broker fails as well.

**Query.** `approval_ca(site)`: the ref and the public half as the loader
read it (`None` before the first `init`; the bindings that need it return a
`Refusal`, as `bind_admin_keys` does without the automation key's half).

**Not chosen: an always-on issuer on a bound host.** For the record, it was
`acme-issuer`'s shape: a type with the key on its one provider, a daily
timer, 30-day certificates, delivery by push. It would have put a CA key at
rest on a managed host.

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
  units: [page.service]
  approval_broker: true
  # It authenticates its own callers: a person's machine by its connection key,
  # a service by its signed request.
  own_auth: true
  secrets:
    - {ns: site, key: ca/approvals, kind: blob, gate: generate, generator: ssh-key,
       pinned: true}
    - {ns: service, key: signing-key, kind: blob, gate: generate, generator: ssh-key}
  params:
    waiting_per_agent: {type: int, default: 5}
    # How often page-sync reads the directory; unused on a local site.
    sync_seconds: {type: int, default: 300}
    # Past this age of directory.json the broker refuses clearances and sign-ins.
    directory_max_age_seconds: {type: int, default: 86400}
    # The most one `page directory extend` may add.
    directory_extend_max_seconds: {type: int, default: 86400}
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
  publication: those machines are no model hosts.
- **TLS** is the binding's `tls`, the site's choice: the requirement is "a
  certificate pledge and services can verify". A pledge and a service hold
  two anchors of different kinds: the site CA's public half for who signed
  what (point 2), and the TLS root or a pinned certificate only for
  reaching the broker.
- **Tier `hub`**, and `hubs_of` (`doc/model/inventory.md`, Hubs) gains the
  reason `approvals`: the broker for every host that provides a type flagged
  `agents`.

### The two inputs

The same two on every kind of site. A person is enabled for the broker
exactly if the site file has the person and `active` of `directory.json`
has the name.

**The site file**, from the model, by the converge of the broker's host.
One derivation, `approval_view(site)`, pure and byte-stable;
`bind_approval_broker` hands it to the role, which writes it in the form
`page load` takes and loads it when it changed:

| Part | From | Notes |
|---|---|---|
| `persons`: login -> `{keys}` | `persons.yml` | the rows that have `approval_keys` and that the model does not hold disabled; `keys` is the field as point 1 has it (the four purposes, each `{key, verified_on?}`) |
| `services`: type -> host -> groups | bindings of types flagged `agents` | point 5; keyed by type and host, since that is the name a call carries |
| `hosts`: name -> host key | the providers of those services | `public/host/<h>/ssh-host-key.pub`, which the loader reads for every converged host (`Site.host_key_public`, `loader.py:499`) |
| `groups`: name -> `{description}` | `identity.yml` `groups` | the groups some binding names; for point 6 |
| `ca`, `settings` | the approvals CA's public half; the binding's params | |

It carries neither `enabled` nor `members`, on any kind. `access`, grants
and host classes are not in it either. A row the model itself holds
disabled (`enabled: false`) is left out, so that such a person is not
enabled for the broker whatever `directory.json` says; this reading of
"persons = name and approval keys" is this note's and is for the designer to
confirm. A host whose public half the store has not written is left out of
`hosts` and is a finding.

**`directory.json`**, on the broker's host:

```json
{"v":1,"source":"hosted-ldap","as_of":"2026-11-19T10:15:00Z",
 "active":["alice","bob"],
 "members":{"rt-operators":["alice"],"admins":[]}}
```

`source` is `model`, `freeipa` or `hosted-ldap`; it is shown and decides
nothing. Every group the site file names is a key of `members`, possibly
empty, and holds only persons that are in `active`. Refused, with the old
file left standing: an unknown member, an unknown or repeated name, an
`as_of` more than 60 seconds ahead. The file is 0644 and replaced by
writing a new one and renaming it.

| Kind | Writer | `active` | `members` |
|---|---|---|---|
| `local` | the converge of the broker's host: a second derivation, `approval_directory(site)` | the rows with `enabled` true | the rows' `groups`, for the groups the site file names |
| `directory` (FreeIPA) | the job `page-sync` | the entry is present and not locked (`nsAccountLock`) | read from the directory |
| `hosted-ldap` | the job `page-sync` | **derived**: a person of the site file is active exactly if the job finds them in at least one group the site file names | read from the provider |

Why `active` is derived on a hosted site: Google's Secure LDAP still
returns a suspended user in a search, and its schema has no status
attribute. The consequence is in point 7.

`approval_directory` is pure like every query; `as_of` is the writer's, set
by the role at the converge, since "a load does not read the clock"
(`doc/model/index.md`, The realm CA's public file).

**The job `page-sync`**: the second binary of p-age, under an account of its
own, on a timer (`sync_seconds`, 300). It reads LDAPS itself and not through
sssd: sssd's cache is of unknown age, and "a group without a POSIX gid is
invisible to SSSD" (`doc/linux.md`, ldap_client).

- Names are the directory's `uid` and `cn` as they are. One that does not
  meet the character rules is left out and counted, never rewritten.
- One bind per run; one search per named group, read from `memberUid`; a
  member DN under the groups base is followed by the job (depth at most 8,
  loops cut).
- A named group that is not found is a failed run, not an empty group. Any
  error (`ADMIN_LIMIT_EXCEEDED` too) writes nothing; no retry inside a run.
  The same rule `ipa_access_exporter` has for the same reason: "an empty
  answer would read as everyone removed" (`doc/identity.md`).

What the model gives the job, through the broker's binding:

| | `hosted-ldap` | `directory` (FreeIPA) |
|---|---|---|
| the groups to read | the groups the bindings name | the same |
| where | the provider's `uri`, `users` and `groups` bases (`hosted.hosted_ldap(site)`) | the directory's `ldaps` endpoint and the `directory` block's containers |
| the credential | the host's own client certificate, the slot `host/<h>/ldap-client` (a record `{certificate, key}`, `catalogue/slots.yml:21-24`), which every converged host of such a site has already; handed to the unit by systemd `LoadCredential` | a read-only bind account contributed by the type, with its password slot (J9, deferred) |
| the server's trust | the distribution's CA bundle, as `ldap_client` verifies it | the realm CA (`realm_ca` on the type) |
| a flow | none to a site host: the provider is outside the site, and the product renders no host egress fence (`doc/model/policy.md`, Egress) | derived, the broker's host to `ldaps`, as `idp-federation` |

So on a hosted site the job needs no bind account, no realm CA and no new
flow. The provider's LDAP client must have "read group information" for
the units it serves, and a change there "takes up to a day"
(`doc/linux.md`, ldap_client, Traps).

**Freshness.** On a local site the file never ages: it changes only with a
converge, as the model does. On the two directory kinds the broker measures
`as_of` against `directory_max_age_seconds` (86400): past it every
clearance and every sign-in is refused (`directory-stale`), while blocks
and withdrawals keep working. An administrator prolongs with
`page directory extend <hours>`: at most `directory_extend_max_seconds`
(24 hours) per call, repeatable, no total cap, each call recorded with who
made it and tied to that `as_of`, ended by the next good file or by
`page directory resume`.

**Loader checks.** One per site; every group a binding names exists;
`sync_seconds` below `directory_max_age_seconds`; on a local site every
named group has a `gid`, as any group a person names does already.

**Cost without approvals.** None; the type is unbound.

## 5. A service that offers actions to agents

A type says it with a flag, and the site says whose agents may use it on the
binding (decided: the binding's `groups` is the one home):

```yaml
# service-types.yml
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
`remote-console` takes `admin_groups`. Two bindings of one type name
different groups for different hosts. Any group passes, role or
entitlement; on a hosted site it is a group of the provider, named by its
`cn`.

**The name** (decided, J3: `probe`). `<service>` in `<service>@<host>` and
in a call is the type's name, not the binding's: `probe` on every host. So a
host provides at most one service of a type flagged `agents`, refused at
load otherwise, and such a type's name full-matches `[a-z][a-z0-9-]*` (a
model slug may start with a digit; the format may not), checked when the
catalogue loads. `<host>` is the model's host name, a slug.

**The persons' rule is not derived from `groups`.**
[`crates/p-robe/SPEC.md`](../crates/p-robe/SPEC.md) says the sudo rule by
which a person calls the dispatcher "has nothing to do with agents". It
stays a site grant in `identity.yml`. Two facts, two homes.

**On each provider**, by a role bound through `bind_agent_service`:

| What | How |
|---|---|
| the program | a release artefact named by role options with its checksum, as `diag_wheel` and `diag_wheel_sha256` are (`doc/observability.md`); empty: nothing installed |
| its account | a system user the role creates (decided, J6; see C5) |
| its signing key | made on the host by the role when absent, Ed25519, readable by the account only. No slot: nobody off the host needs its public half, and a reinstalled host makes a new one and certifies it |
| its certificate | a kit program on a timer, as root: the host's SSH host key signs the service's public key under `<type>@<host>`, valid 30 days, reissued after 20 or when the key changed. The roll-out installs the timer; renewal needs no converge |
| the allowed-signers file | the two lines of point 3, from the approvals CA's public half; a `Refusal` while the half is absent |
| the dispatcher's rule for the account | a local sudoers file checked with `visudo -cf`, as `diag` writes its own and as `ldap_client` writes a hosted site's grants (`/etc/sudoers.d/fundament-grants`); see C5 |

**Which host key, and where a wrong one is refused:**

- **The type.** A host needs an Ed25519 or ECDSA P-256 host key to run a
  service. For a managed host the model's key is the `ssh-host-key` slot,
  generated by `ssh-key`, whose default is Ed25519 and whose slot row sets
  no `type` (`catalogue/slots.yml`); the store's import check holds an
  imported value to the slot's type. So the key the site holds is Ed25519
  by construction. The loader still checks the half it read for each
  provider of a type flagged `agents`: any other type is a load problem
  naming the host. An RSA key can thus only be a live key the site does not
  hold, which the next check refuses.
- **The live key.** "An adopted host keeps its own key until host-key
  delivery installs the generated one" (`doc/converge/index.md`, Host keys;
  read on `main`). The role compares the host's live key of that type with
  the bound half and fails by name when they differ or the key is absent;
  the timer's program makes the same comparison before every signature.
- **Beside the site's host certificates.** On a site with `site_ca` every
  converged host's Ed25519 host key also carries a host certificate from
  `site/ca/ssh` (`doc/linux.md`, ssh_host_cert). That is for clients'
  `known_hosts` and has no part here: the service's certificate is issued
  *by* the host key, and verifiers take the host key from the signed list
  of point 6.

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

**Not chosen: the site CA certifying service keys** (decided, J8: the host's
key certifies). For the record, it would have made the service's key a
generated host slot of the type and given the issuer a third name form,
`<type>@<host>`; the host timer, the host-key checks, `approval_hosts`, the
`hosts` part of the site file, the signed list of point 6 and the name
`hosts` would have gone. With the operator as issuer, every service's
certificate would then have renewed only at a converge.

**Cost without approvals.** None; the flag is on unbound types.

## 6. What a person's machine receives

Through the broker, which carries and cannot alter what the site CA signed:

- **Renewed certificates.** Public data, in no slot; from the converge to
  the broker's host as files. They are delivered beside the site file and
  are not part of it: `approval_view` holds no certificate.
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
  it has left the site file with the same converge and the broker passes on
  nothing from a host it does not know. The list exists because a service's
  key is certified by its host's key (decided, J8).
- **Group names and descriptions**: `groups` of the site file. A group's
  `description` is optional in the model; one without gives its name alone.
  Which groups are a person's comes from `directory.json`.
- **The trust anchor** is not received this way: the committed public half
  of the approvals CA's key is what an administrator hands over.

## 7. Disabling and leaving

**At once, on every kind:** an administrator blocks the person at the broker
(`page block`). It is not model data.

What then makes the person not enabled for the broker, per kind:

| Kind | The step | When it holds | What the next converge of the broker's host adds |
|---|---|---|---|
| `local` | `enabled: false` with `left` in `persons.yml` (`left` is set exactly when `enabled` is false, `doc/model/people.md`) | with a converge of the broker's host, which writes `directory.json` and the site file | nothing more; `approval_signers` no longer lists the person, so nothing is renewed |
| `directory` (FreeIPA) | the person is locked or removed from the groups in the directory | within one run of `page-sync` | the row's keys leave the site file once the row is disabled or gone; no renewal |
| `hosted-ldap` | the person is removed from the groups at the provider | within one run of `page-sync`: in no named group, so not in `active` | the row's keys leave the site file once the row is gone; no renewal |

For a local site the order stays: block, the edit, a limited converge of the
broker's host (`fundament converge --limit <broker's host>`; tier `hub`
converges last, so a whole-site run that stops earlier has not told the
broker), then the rest.

**The decided limit on a hosted site.** `active` there means "in at least
one named group". An account that is only suspended at the provider and
keeps its groups therefore keeps approving, until its groups are removed or
it is blocked. The owner accepts this. The site's leaver instructions say:
offboard through the playbook; a suspension made by hand is followed by
`page block`.

**What `offboard` does today on a hosted site**
(`collections/ansible_collections/fundament/identity/plugins/module_utils/workspace.py`,
`offboard_plan` and `offboard_apply`, lines 164 to 183;
`identity/playbooks/offboard.yml`): it suspends the user, then removes every
direct group membership the provider lists for them, then signs them out,
then ends the services' own sessions. So a leaver offboarded through the
playbook is out of every named group and not active after the next run of
`page-sync`. Two things about it are owed (next section).

**What remains, on every kind:** certificates on the person's machine, valid
for up to 90 days. They matter only if the broker fails as well.

**`retire`** later, as for any person. `retired_uids` keeps the login from
being handed out again (`doc/model/people.md`, Retired ids; on a hosted site
`onboard` never allocates a retired uid, `doc/identity.md`), so a leftover
`<login>:confirmed` certificate can never name a later person.

**A lost machine** is the block replaced (point 1), after the block at the
broker. The next converge of the broker's host certifies the new keys at
once. The model keeps no list of ended keys.

Not built as a delivery (decided, J7): the block at the broker is not a
`deliveries` step of the broker's type.

## 8. What fundament owes

Registered at the owner's word. First the two changes to what exists, then
what the model lacks for the points above.

**In `offboard`, on a site that has a broker:**

1. **First `page block <person>` on the broker's host.** It is immediate and
   recorded, and it makes a run that fails halfway harmless: whatever the
   provider's steps got to, the person approves nothing. The playbook
   already has the shape for a step on a site host: its second play ends
   the dashboards' sessions on their hosts.
2. **The removals before the suspension.** Today the order is suspend, then
   remove from the groups. A run that fails between the two leaves an
   account that is suspended and still a member, which by the hosted site's
   definition of `active` still approves. With the removals first, a failed
   run never leaves that state.

Not covered by either, and not verified: a membership that comes only
through a nested group. `offboard` lists the user's direct groups;
`page-sync` follows member DNs under the groups base.

**What the model lacks:**

| Lacking | For |
|---|---|
| `approval_keys` on a person row, with its checks | point 1 |
| the slot `site/ca/approvals` on the broker's type | point 2 |
| `site_ca_sign`: user certificates with one principal and nothing else; an SSHSIG; not refused without `site_ca` | point 2 |
| the type `approval-broker`, its flag, its one-per-site check | point 4 |
| the params `sync_seconds`, `directory_max_age_seconds`, `directory_extend_max_seconds`, `waiting_per_agent` | point 4 |
| `approval_view(site)` without `enabled` and `members` | point 4 |
| the second derivation `approval_directory(site)` for a local site, and a role that writes it with `as_of` | point 4 |
| the job's inputs in `bind_approval_broker`: the group list, the provider's `uri`, `users` and `groups` bases, the `Lookup` of `host/<h>/ldap-client` | point 4 |
| a unit that exists on some kinds only: a type's `units` is one list, and `page-sync`'s timer does not exist on a local site, where `monitored_units` would then watch a unit that is not there | point 4; the same want of a backend condition as J9 |
| a rule pack over the age of `directory.json`, beside the one over the certificates' days left | points 2 and 4 |
| the flag `agents`, the required `groups` param, the checks on the type's name and one service per host | point 5 |
| the derived flow `approval-<host>-<service>`; the `hubs_of` reason | point 4 |
| `approval_hosts(site)`, `approval_signers(site)`, `approval_ca(site)`, `agent_services(site)` | points 2, 5, 6 |
| the role and its row for a provider of an `agents` type; the kit program that certifies with the host key | point 5 |
| for a FreeIPA site, later: the bind account's condition (J9), the realm CA flag, the flow to `ldaps` | point 4 |

## 9. diag-tools

Until `probe` has replaced it, nothing of it changes, and the two share
nothing. Today's wiring, by file (read on `main`):

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
  noun" (`crates/p-robe/SPEC.md`);
- the verbs about a site as a whole (`mon`, `id`), which
  `crates/p-robe/SPEC.md` leaves to a later second service.

## Conflicts

Numbered as in the first writing.

**C1. A design note, and designing ahead. Decided:** the note stays in
procession until a site is about to bind the broker; then it is built, and
`doc/model/approvals.md` is written as the reference of what was built.
fundament has neither a design note nor designing ahead (its `CLAUDE.md`),
which is why it is not placed there now.

**C2. Who is active and who is in which group. Decided,** as point 4 has
it. The model holds memberships only on a local site; on the other two,
`groups` on a person row is refused (`doc/model/people.md`), and on a
hosted site `enabled` is not the model's either. So neither is in the site
file on any kind: both are in `directory.json`, written from the model by
the converge on a local site and from the directory by `page-sync` on the
other two. The earlier writings cited `vpn_identities` as the model's
precedent for "expanded from the directory"; on `develop` nothing consumes
it outside the model (`people.py:490`, `:522`), so the job is new in kind,
and what it copies from the product is `ipa_access_exporter`'s rule for a
failed read.

**C3. "On every change, and at least hourly." Settled.** The requirement is
withdrawn: nothing scheduled depends on a converge.

**C4. "TLS from the site's own certificate authority." Settled.** The
requirement is any certificate pledge and services can verify, left to the
binding's `tls`. (`develop` has `site/ca/x509` on a site with `site_ca`;
whether `tls: internal-ca` now reads it was not checked beyond a search
that found no reader in `bindings.py`, `edge.py` and `load_edge.py`.)

**C5. An account for a service, and its sudo rule. Decided through J6:** the
role makes the account. The fact behind it stands: `accounts` are `bind`,
`service` and `shared`, a command account is a forced command over SSH, a
daemon's own system user is neither, and a catalogue grant's `account` must
be an identity account or a command account of its own entry
(`load_identity.py`; read on `main`). So the rule that lets the service run
the dispatcher is the role's own file and is not in `grants_on`.

**C6. The command (U6) and grants. Settled as out of scope.** Stage 4.

## Open, for the owner

**E. Whether a hosted site keeps a `persons.yml` row for those who approve.
Open.** The row would hold `approval_keys` and nothing else of substance.
The designer recommends yes: the operator certifies the keys at the
converge, so they must be where the converge reads; the repository gives
them a reviewed history; and the provider's `sshPublicKeys` is a list of
login keys, which must never be the same list. From fundament's side: a
hosted site's `persons.yml` "may be empty", and a row the site keeps "is a
directory site's: `groups` refused, `uid` a pin inside the range"
(`doc/model/people.md:36-37`), so such a row is admitted. Two things to
settle with it. A row needs `given` and `family`, and `profile` unless the
site has a `default_profile` (`model/README.md#personsyml`, read on `main`;
not re-read on `develop`), so "nothing else" means those too unless the
loader is relaxed. And `onboard` takes its person from a `persons.yml` row,
so a site that onboards through the playbook has the row anyway; the first
hosted site's file is `{}` today. *This note's recommendation:* yes, the
row, for the designer's reasons; the alternative is a second home for
approval keys, which the model has no shape for.

**Whether the first sandboxes separate model and signer. Open.** Not a
model question; this note has nothing on it.

**Decided, with what each rested on:**

- **J1.** The operator is the issuer, at a converge. `develop` already
  signs that way for host certificates (`site_ca_sign`).
- **J2.** The flags, the field, the flow and `approval-broker` in the
  product; `probe` as a site type on the first site and a product row once
  a second site binds it. Basis: "a fact only one site has is site data"
  (the port workspace's `CLAUDE.md`).
- **J3.** The service's name is `probe`. It is on the wire and in every
  service certificate, so it is settled before the first site binds it.
- **J4.** One `verified_on` per key, the `keys` row's shape.
- **J5.** The persons' dispatcher rule is not derived from `groups`.
- **J6.** The service's account is made by its role, as the product's other
  daemons are (the observability roles create their users in their tasks);
  a third account kind for grants when a second service needs it.
- **J7.** The leaver's block is not a delivery. No people converge reads
  deliveries, and a profile must name every active delivery.
- **J8.** A service's key is certified by its host's key.
- **J9. Deferred.** It falls away for `hosted-ldap`, where the job uses the
  host's client certificate. For a FreeIPA site it stays as it was: a bind
  account contributed by a type should derive on a directory site only,
  since a bind account is "a directory entry that never logs in"
  (`doc/model/people.md`, Accounts). To be taken up when that site is
  ported.

## Report

**What was read for this writing**, in fundament at `develop` 8b6fe8f,
read-only, through `git show` and `git grep` (the checkout itself is on
`main`): `doc/model/people.md` (The backend is derived, A hosted directory,
VPN identities, the last section); `doc/linux.md` (ldap_client, and the
lines on ssh_host_cert); `doc/identity.md` (People on a hosted directory,
the playbook table); `doc/core.md` (site_ca_sign); `doc/model/secrets.md`
(The site CA); `model/README.md` (the `site.yml` providers, the backend
paragraph); `catalogue/slots.yml` (the `ldap-client`, `hosted-ldap` and
`site-ca` rows) and `catalogue/profiles.yml` (the `ldap_client` row);
`hosted.py` (its head, `estate_group_mail`); `people.py` (`estate_persons`,
`vpn_identities`); `loader.py:499` and `_check.py:42`; the role
`ldap_client`'s README; the identity collection's README, `offboard.yml`,
`module_utils/workspace.py` (group members, the onboard and offboard
plans), the head of `lookup/people.py`; `doc/secret-store/index.md` (the
generator table's two CA rows). In the port workspace: `dai/main`'s
`README.md` (by search), `persons.yml`, and lines of `cloud.yml`,
`people.yml`, `identity.yml`.

**Still as read on `main` on 2026-11-11, not re-read on `develop`:**
everything else this note cites: the catalogue's blocks and the active
rule, `doc/model/policy.md`, `inventory.md`, `operations.md`, `roles.md`,
`doc/converge/index.md`, `doc/observability.md`, the grant check in
`load_identity.py`, `bind_diag`, the person row's required fields, point 9
as a whole.

**Not read at all:** the branches `agent/*`; the port workspace's `tum/`,
`c-it-work/`, `specs/` and `dai/main/SECRETS.md`; the loader's code for the
hosted backend beyond `hosted.py`'s head; `site_ca_sign`'s code.

**Verified by reading, on `develop`:**

- Three backends, `hosted-ldap` derived from a `site.yml` provider, refused
  beside a directory service.
- `site/ca/x509` and `site/ca/ssh` exist on a site with `site_ca`; no host's
  scope holds them; `site_ca_sign` signs in the controller process, issues
  host certificates only for `kind: ssh`, and is refused without `site_ca`.
- Every converged host of a hosted site has the slot
  `host/<host>/ldap-client`, a record `{certificate, key}`, imported.
- `offboard` suspends, then removes the direct group memberships, then
  signs out.
- `vpn_identities` has no consumer outside the model.
- No search hit for a reader of `internal-ca` in `bindings.py`, `edge.py`,
  `load_edge.py`.

**Not verified:**

- Nothing was run: no load, no test, no converge, no `ssh-keygen`, no LDAP
  query.
- Everything said about Google's Secure LDAP itself (a suspended user is
  still returned, no status attribute, `memberUid`, member DNs, admin
  limits) is the designer's, taken from the orchestrator; this note read
  only what fundament's documents say of the provider.
- That the provider's client certificate, which `ldap_client` installs for
  sssd, may also be used by a second program on the same host, and that
  `LoadCredential` suits it.
- That `nsAccountLock` is how a FreeIPA entry shows a disabled person.
- That `site_ca_sign` can be extended as point 2 says without changing what
  it does today; its code was not read.
- That `ssh-keygen -Y verify` accepts, in every detail, the certificates a
  controller-side builder or a host key as issuer would make; the two
  allowed-signers lines.
- Whether a person row with `approval_keys` and little else loads on a
  hosted site today (E).
- Whether `offboard`'s listing of a user's groups misses nested
  memberships.
- Whether a failed tier stops the tiers after it, which the local site's
  leaver order assumes as the worst case.
- Whether fundament's token check, which lives outside the product, admits
  the approval system's program names and namespaces in the product.
- Ports, unit names, program names and type names other than `probe` in the
  YAML are placeholders.
