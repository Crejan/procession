# p-lace - specification (draft)

Resources and who holds them: a register of things people reserve, and the
service that keeps it. Binary `place`.

A resource is anything a person can hold for a while: a workstation, a
realtime host, a GPU server, a lab instrument, a power drill. Holding it is
a fact others can see, and nothing more: what one does with the resource is
not the core's business. What follows from a reservation is done beside the
core: a host learns who holds it and warns others at login (`notice`, built
in, section 8); a remote desktop starts on a reserved workstation (`dcv`, an
**adapter**: an executable bound to the core by one generic contract,
sections 7 and 10).

It replaces `dcv-manager` (Python, a web app that reserves remote-desktop
workstations): its reservation becomes the core, its desktop handling the
`dcv` adapter (section 13). `dcv-manager` stays as it is until this has
replaced it.

License: MIT OR Apache-2.0.

Status: a specification. No crate exists. The name is a working name.

## Scope

- One server per site: one register, one database, one web UI. **The
  register is the one source of truth for reservations.** Everything else
  (the file on a host, the seat record of a DCV host, metrics) is a copy or
  a fact of its own, never a second register.
- Callers: people in a browser (behind the site's auth proxy), people on
  the command line (on the server, or on a host for that host), scripts,
  lifecycle tooling, hosts (their own reservation), agents (MCP, through
  the approval system).
- Resources come from the site's provisioning as a file (section 4);
  virtual resources may also be created in the web UI.
- Non-goals in v1: no login of its own (no OIDC, no passwords); no
  calendar of future bookings; no billing or quotas; no inventory beyond
  what is imported; nothing in the core or the UI that knows a particular
  adapter; no notification channels (mail, chat).

## 1. Architecture

```
browser ──▶ auth proxy ──(headers)──▶ ┐
script  ──(token)───────────────────▶ ├─ place serve ── SQLite (the register)
CLI on the server ──(Unix socket)───▶ │     ├─ core: resources, reservations, history, outbox
agent ──(MCP, signed call)──────────▶ │     ├─ notice: read model per host
                                      │     ├─ status sources ──▶ Prometheus
host ── place host sync / claim ────▶ ┘     └─ adapters (exec, JSON in/out)
   │      (host token, pull)                     └─ dcv ──SSH, sudo──▶ seat helpers (seat protocol)
   └─ /run/place/reservation.json ◀── written by place host sync
          ▲ read by PAM, the desktop notice, place host busy
```

- **The core decides, once.** Who holds a resource, whether a reservation
  may be made, extended, shared, handed over or released: one function each,
  one transaction each. Front ends, hosts and adapters never decide this.
- **Adapters react and act; they do not hold.** An adapter learns of a
  change through the core's outbox and acts by its own means; it offers
  actions and status that the core and the UI show without understanding
  them. Its failure never undoes or blocks a reservation; it is shown
  beside it.
- **Hosts pull.** A host asks the server for its own reservation and keeps
  a copy; what runs at login or before a lifecycle action reads only that
  copy. The one path from the server to hosts is the `dcv` adapter's SSH
  to the seat helpers, and only on hosts with that capability.
- One binary: `place serve` is the server, `place host ...` the host side,
  `place adapter dcv` the adapter that ships with the crate, everything
  else the command line.

## 2. Terms

| Term | Meaning |
|---|---|
| person | a human, known by a login name: the name the auth proxy asserts, the name an approval names, and the POSIX login on hosts. All three must be the same name |
| group | a name the auth proxy asserts for a person, the delegation names for an agent (section 6), or a host reports for its local user (8.4) |
| resource | a thing that can be reserved: an id, a kind, labels, attributes, links, an optional status source, who may reserve it, a capacity, its capabilities |
| reservation | one person holding one place of one resource: holder, purpose, since, an optional end, the persons it is shared with |
| holder | the person a reservation belongs to |
| sharee | a person the holder lets use the resource beside them; a sharee holds nothing |
| hand-over | the holder makes another person the holder of the same reservation |
| release | the end of a reservation: by the holder, by an administrator, by its end time, or because its resource was retired |
| administrator | a person in a group of the resource's `admin_groups` or of the server's `admin_groups` |
| capability | a name a resource lists, with settings: `notice` (built in) or the name of an adapter (`dcv`) |
| adapter | the executable the configuration binds to a capability, called by the core under the contract of section 7 |
| source | who owns a resource's definition: an import source by name, or `ui` |

## 3. Core

### 3.1 Resource

| Field | Type | Meaning |
|---|---|---|
| `id` | `[a-z0-9][a-z0-9._-]{0,62}` | unique on the server; for a machine, its short host name by convention |
| `kind` | same charset | free word: `workstation`, `realtime-host`, `instrument`, `tool`. Filters and templates use it; the core gives it no meaning |
| `name` | text, 1-100 chars | display name; defaults to `id` |
| `labels` | map text → text | for filters and link templates (`room`, `team`, `class`) |
| `attributes` | map text → JSON value | facts shown on the resource page (hardware: CPU, memory, GPUs, serial numbers). Shown, never interpreted |
| `links` | list of `{title, url}` | `url` a template (section 3.4) |
| `status` | optional `{query, facts}` | a status source (section 9) |
| `reserve_groups` | list of group names | who may reserve; empty means nobody but administrators |
| `admin_groups` | list of group names | who may administer this resource in addition to the server's administrators |
| `capacity` | integer ≥ 1, default 1 | how many reservations may run at once. 1 is exclusive. A person holds at most one place of a resource |
| `capabilities` | map capability → settings (JSON object) | `notice` and adapters, with their settings; an adapter's settings are validated against its `settings` schema (7.2) |
| `note` | text ≤ 200 chars | a free note anyone who may reserve may edit (dcv-manager's description); not part of the import |
| `source` | text | `ui` or the import source's name |
| `retired` | timestamp or none | retired resources take no new reservation and are hidden by default |

### 3.2 Reservation

| Field | Type | Meaning |
|---|---|---|
| `id` | UUID v7 | |
| `resource`, `holder` | | |
| `purpose` | text ≤ 200 chars, may be empty | what the holder says they do; shown to everyone, and in the host notice |
| `since` | timestamp | |
| `until` | timestamp or none | none (the default) means open-ended: the reservation never expires and ends only by a release. With an end, the server releases it at that moment |
| `shared_with` | list of persons | |
| `logins` | list of logins | further accounts the holder uses on the resource (a shared desktop account, 10.2); set by an adapter action, never by the core |

**A reservation never expires unless it was made with an end.** That is
the existing seat protocol's rule and dcv-manager's practice, and it is
kept: an abandoned reservation is freed by an administrator, not by a
timer. A reservation with an end is released by the server at that time
(checked every 30 seconds; the release is recorded with reason `ended`).

### 3.3 Operations and who may do them

| Operation | Who | Rule |
|---|---|---|
| reserve | a person in `reserve_groups` | resource not retired; fewer than `capacity` reservations; the person holds none of it. `until`, if given, in the future, at most `max_until` ahead (setting, default 90 days) |
| extend | holder, administrator | sets, moves or removes `until` |
| share / unshare | holder, administrator | sharees must be persons the server has seen (5.4) |
| hand over | holder, administrator | the new holder must be in `reserve_groups` and hold none of the resource |
| release | holder | |
| release another's | administrator | recorded with who did it; the holder sees it on their next visit |
| adopt | administrator | makes a reservation for a holder an adapter reports (drift, 10.3); the same rules as reserve except `reserve_groups` |
| edit note | anyone in `reserve_groups`, administrator | |
| an adapter's action | as the action's `requires` says (7.2) | checked by the core before the adapter is called; administrators may run every action |
| create, edit, retire a resource with source `ui` | administrator (server's `admin_groups`) | imported resources are edited only by their import |

Each operation is one SQLite transaction (`BEGIN IMMEDIATE`): check and
write together, so two people pressing "reserve" at once get one
reservation and one refusal. A partial unique index on (resource, holder)
for open reservations is the second line.

Every change appends an **event** (append-only table): what, resource,
reservation, by whom, through which surface (web, api, cli, host, mcp with
the call's identifier, server for `ended`), when, and the reason for a
release (`holder`, `admin`, `ended`, `retired`). The history of a resource
is its events, including adapter actions (never their secret results).

### 3.4 Link templates

A link's `url` is a `minijinja` template over `id`, `kind`, `name`,
`labels`, `attributes`; values are inserted URL-encoded (the server's
auto-escape for this template kind), so a label cannot break out of its
query parameter. The result must be an `http` or `https` URL, else the
link is dropped and the import reports it. Example:
`https://grafana.example.org/d/node?var-instance={{ id }}.example.org`.
Server-wide templates per kind (`[links.<kind>]` in the configuration)
apply to every resource of that kind.

## 4. Import from provisioning

The provisioning model knows the machines, their hardware, who may use
them and what runs on them; place should not be told twice. The site's
provisioning renders one JSON file per source and runs `place import`
(or `PUT /api/v1/import/<source>`) with it.

```json
{
  "schema_version": 1,
  "source": "provisioning",
  "resources": [
    {
      "id": "ws01",
      "kind": "workstation",
      "name": "Workstation 01",
      "labels": {"room": "r101"},
      "attributes": {"cpu": "16 cores", "memory_gib": 128, "gpus": ["GPU model A"]},
      "links": [{"title": "Dashboard", "url": "https://grafana.example.org/d/node?var-host={{ id }}"}],
      "status": {"query": "up{instance=\"{{ id }}.example.org:9100\"}"},
      "reserve_groups": ["ws-users"],
      "admin_groups": ["ws-admins"],
      "capacity": 1,
      "capabilities": {
        "notice": {"mode": "warn"},
        "dcv": {"host": "ws01.example.org", "sessions": ["gnome-classic", "kde"], "accounts": ["shared01"]}
      }
    },
    {
      "id": "rt03",
      "kind": "realtime-host",
      "reserve_groups": ["rt-users"],
      "capabilities": {"notice": {"mode": "enforce"}}
    },
    {"id": "drill1", "kind": "tool", "reserve_groups": ["workshop"]}
  ]
}
```

- **Declarative.** The file is the whole set of resources of that source.
  A resource in the file is created or updated; a resource of that source
  not in the file is retired. Resources of other sources and of `ui` are
  not touched. An `id` that belongs to another source is refused (the
  whole import, naming the id).
- **Retired, not deleted.** A retired resource keeps its open reservations
  until they are released (the holder is shown that it is retired) and
  takes no new one. Its history stays. Coming back in a later import
  un-retires it.
- **All or nothing.** The import is checked first (schema, charsets,
  templates, a capability that is neither `notice` nor a configured
  adapter, capability settings against their schema), then applied in one
  transaction. `place import --check` prints the difference (created,
  changed fields, retired) and applies nothing.
- Unknown fields are refused, not ignored: a typo in `reserve_groups`
  would otherwise make a resource unreservable silently.
- Parsed with `serde` / `serde_json` into typed structs
  (`deny_unknown_fields`); adapter settings with `jsonschema`. The file is
  JSON because provisioning tools render JSON without help; the
  configuration stays TOML (conventions).

Virtual resources (a drill, an instrument) are created with source `ui` in
the web UI or by `place resource add`, with the same fields.

## 5. Identity and the trust boundary

place has no login. It learns who is calling in exactly one way per
entrance; each entrance has its own listener or credential, so that one
entrance's credentials cannot be presented at another.

| Entrance | Listener (default) | Who it is | Trusted for |
|---|---|---|---|
| web UI and HTTP API | TCP `127.0.0.1:8470` | the auth proxy's headers, only from `trusted_proxies` | person and groups |
| tokens | the same listener | `Authorization: Bearer` | a token's owner and scope (5.3) |
| command line on the server | Unix socket `/run/p-lace/place.sock`, mode 0666 | `SO_PEERCRED` uid → login; groups from NSS | person and groups |
| agents | TCP `mcp_listen`, off by default | the approval system (section 6) | person and the delegation's groups |

### 5.1 The auth proxy

A reverse proxy in front of place authenticates the browser (with the
site's identity provider; that is the proxy's business) and adds headers:
`user_header` (default `Remote-User`, the login), `groups_header`
(`Remote-Groups`, comma-separated), `name_header` (`Remote-Name`),
`email_header` (`Remote-Email`). These are the names forward-auth gates
commonly use; each is configurable.

**The trust boundary is the TCP peer.** place accepts identity headers
only on a connection whose peer address is in `trusted_proxies`
(addresses or prefixes; default `127.0.0.1/32`, `::1/128`). From any other
peer, a request that carries one of the identity headers is refused with
400 and logged at warning: a misconfigured proxy or a direct caller shows
up at once instead of being treated as anonymous. place never reads
`X-Forwarded-For` for this decision.

- The proxy **must remove** these headers from the client's request before
  adding its own. If it does not, anyone who reaches the proxy is anyone.
  This is the proxy's configuration, and the documentation gives it for
  the common proxies; place cannot check it.
- The groups are taken as asserted, at each request. Removing a person
  from a group takes effect at their next request.
- A login with no groups is a person in no group: they see the register
  and may reserve nothing.
- Without a login header from a trusted peer, the API answers 401 and the
  UI a page that says the proxy sent no identity.

### 5.2 The Unix socket

For the command line on the server itself (`place` with no `--server`).
`tokio::net::UnixStream::peer_cred` gives the uid; the login is its passwd
name, the groups `nix::unistd::getgrouplist`. Root is an administrator.
Every local account may connect; identity is the kernel's (p-layer's
shape).

### 5.3 Tokens

A token is for what has no browser. Stored as SHA-256 (`sha2`) of 32
random bytes (`getrandom`), shown once, compared in constant time
(`subtle`); each has an optional end; `place token create|list|revoke`.

| Scope | Made by | May |
|---|---|---|
| `read` | administrator | every `GET` of the API: scripts, lifecycle tooling on a controller |
| `host:<resource>` | administrator, or provisioning through `place token create --host <id>` | read the notice and `busy` of that one resource; reserve and release **that resource only, only for the login the request names**, with the groups the request names (8.4) |
| `person` | a person for themselves in the web UI | the API as that person, with the groups they had when they last came through the proxy (refreshed on each visit); never the token, import and resource-administration routes |

The auth proxy must let requests with `Authorization: Bearer place_...`
through to place without its own login. That is proxy configuration; a
site that will not do it lets hosts and scripts reach the listener
directly.

### 5.4 Persons

place keeps a row per person it has seen: login, display name, mail,
groups as last asserted, last seen. It is a cache for display and for
picking sharees, never a source of rights: rights come from the current
request's identity. A person no proxy and no host ever asserted cannot be
a sharee or a new holder.

### 5.5 What place trusts, and what it is trusted for

| Party | Trusted for | Taken over, it can |
|---|---|---|
| the auth proxy | who a browser user is, and their groups | act as any person |
| a host, by its `host:` token | who its calling local user is, and their groups, for its own resource only | reserve and release its own resource as any login it names. That is all a host's root could do anyway; root on a host can do anything on that host |
| place, for hosts with `notice` | who holds them | write any notice; under `enforce`, deny login to accounts that are not exempt. It cannot let anyone in: the gate only adds a denial on top of the host's own PAM stack. It has no credential on those hosts |
| place, for DCV hosts | nothing new: it holds the seat protocol's manager account | claim and release seats on every DCV host (as dcv-manager can today) |
| place, for lifecycle tooling | whether to wait | make it wait, or let it go ahead |
| adapters | doing what their `describe` says | whatever their own credentials allow. They run as the server's account; the configuration names them, never the import or a user |

## 6. MCP, through the approval system

Agents reach place as a **service** of the approval system
([`doc/approvals.md`](../../doc/approvals.md)), exactly as p-robe's
service: MCP over HTTP at `POST /mcp`, stateless, the signed call in the
tool call's `_meta` (`procession/call`, `procession/call_sig`), the tool's
arguments equal to the signed call, nothing done without an approval from
the agent's person and, from stage 2, the broker's clearance
([`crates/p-robe/proposals/agent-to-service.md`](../p-robe/proposals/agent-to-service.md)).
The service name in a call is `place`. place does not implement that
exchange itself: the service side (checking approval and clearance, used
identifiers on disk, the request to the broker) is the code `probe serve`
uses, which belongs in `p-act` behind a feature so that both services
share it. place adds its tool table and its ratings.

Why the approval system and not a token: an agent has no identity of its
own and no account (R2); its person must answer for what it does (R1). A
token in a sandbox would be a person's whole power with nobody asked.

**Who the agent acts for.** The person is the one the approval names. The
groups are the delegation's (`groups@procession` in the certificate inside
the call's signature, `approval-formats.md` 3.1): a person delegates only
groups they are in (R3), and from stage 3 the broker checks the person and
the binding's `groups` (R10). place then applies its own rules (3.3) to
that person and those groups, as for any other caller.

The MCP layer is `rmcp` (server, streamable HTTP transport in stateless
mode, no session id), with the `_meta` members read from the request
context.

### 6.1 Tools and ratings

Ratings per `doc/approvals.md` R4: exposure, damage, disruption, the
worst case for the concrete parameters; the rule for the concrete case is
data, not code.

Core tools:

| Tool | Arguments | Exposure | Damage | Disruption |
|---|---|---|---|---|
| `place_list` | filters (kind, label, state, mine) | `open` | `none` | `none` |
| `place_who` | `resource` | `open` | `none` | `none` |
| `place_reserve` | `resource`, `purpose`, optional `until` | `open` | `recoverable` | `none` |
| `place_extend` | `resource`, `until` or none | `open` | `recoverable` | `none` |
| `place_release` | `resource`, `holder` | see below | | |

`place_release` names the holder explicitly, so that the person's dialog
says whose reservation ends (R9):

| Case | Exposure | Damage | Disruption |
|---|---|---|---|
| `holder` is the person; no adapter reports the resource `in_use` (7.2) | `open` | `recoverable` | `none` |
| `holder` is the person; an adapter reports it `in_use` | `open` | `lasting` | `outage` |
| `holder` is someone else | `open` | `lasting` | `outage` |

Adapter tools are generated from `describe` (7.2): one tool per action,
named `place_<capability>_<action>` (`-` becomes `_`), its arguments
`resource` plus the action's parameter schema, its rating the one the
action declares. An action whose result is `secret-url` is not offered as
a tool: a connect link is a bearer secret and does not belong in a
model's context.

Exposure of the core tools is `open`: who holds what is shown to every
person who may see the register. With the default automatic ceiling
(`open`, `none`, `none`) listing is automatic and every change is asked;
a person can let an agent reserve and extend unasked by raising damage to
`recoverable`, and nothing else.

**Releasing someone else's reservation** is rated at the top of two
scales, so it is never automatic: the person is asked, with a presence
check, and signs with their confirmed approval key (R4). place then
requires that person to be an administrator of the resource, by the
delegation's groups; otherwise the outcome is `refused` and nothing is
asked of anyone else. The approval is the agent's person's, not the
holder's: a request to another person is not part of the approval system
yet (`doc/approvals.md`, section 9). When it is, this case becomes a
request to the holder, with the administrator's approval as the path for a
holder who is gone. The event records the call's identifier.

Not offered to agents: share, hand over, adopt, note, import, resource
administration, tokens, and adapter actions with secret results.

## 7. The adapter contract

### 7.1 Executables

An adapter is an executable, in any language, that the core runs once per
question with JSON on standard input, JSON on standard output, an exit
code and a time limit. The precedents are monitoring plugins (Nagios and
its successors: a program, an exit code with a fixed meaning, a
documented output) and git hooks (a program at a known place, input on
stdin, the exit code decides). It is chosen because of:

- **any language**: a site writes an adapter for its instrument booking
  system in a shell script or Python, without touching Rust;
- **crash isolation**: an adapter that hangs is killed at its time limit;
  one that panics or leaks takes nothing of the server with it;
- **no rebuild**: a new capability is a file and a few lines of
  configuration, not a release of place.

The cost is a process per call (milliseconds), which the call rates here
(events, a click, a status refresh) bear easily. The alternatives are in
"Rejected alternatives".

The adapter that ships with place (`dcv`, as `place adapter dcv`) uses
this contract and nothing else: it is the contract's first test, and a
site may replace it with its own program.

### 7.2 Calls

The configuration binds a capability to a command:

```toml
[adapters.dcv]
command = ["/usr/bin/place", "adapter", "dcv"]
timeout = "60s"
```

The core runs `command` with one more argument, the verb, and writes one
JSON object to stdin; every object in and out has `schema_version`, and
every input carries `config`: the other keys of the adapter's
configuration table. Process handling with `tokio::process` (own process
group, killed with the group at the time limit, `kill_on_drop`); stdout
limited to 1 MiB, stderr kept (64 KiB) for the log and the "needs
attention" view.

| Verb | stdin | stdout |
|---|---|---|
| `describe` | `{}` | the adapter's description (below) |
| `status` | `resource` (with this capability's settings), its open `reservations` | `{"fields": {...}, "in_use": bool, "foreign_holder": login or null}` |
| `act` | `resource`, `reservations`, `action`, `params`, `caller` (login, name, mail, groups) | `{"result": ...}` per the action's `result` kind, optional `reservation_logins` |
| `event` | `event` (`reserved`, `released`, `handed-over`), `resource`, the reservation before and after | `{}` |

Exit codes: 0 done; 1 refused (stdout `{"message": ...}`, shown to the
caller as the reason); 2 the adapter cannot reach its target now (retry);
anything else, a signal or the time limit: failed. Non-JSON output on
exit 0 is a failure.

`describe` declares:

```json
{"schema_version": 1, "capability": "dcv",
 "settings": {"type": "object", "properties": {"host": {"type": "string"}}, "required": ["host"]},
 "status": [{"name": "desktop", "title": "Desktop running", "type": "bool"},
            {"name": "seat_holder", "title": "Seat held on host by", "type": "text"}],
 "actions": [{"name": "connect", "title": "Connect (new link)", "requires": "holder-or-sharee",
              "params": {"type": "object", "properties": {}}, "result": "secret-url",
              "rating": {"exposure": "secret", "damage": "none", "disruption": "none"}}],
 "events": ["released", "handed-over"]}
```

- `settings`: JSON Schema for the capability's settings on a resource,
  checked at import (`jsonschema`).
- `status`: fields with a type (`text`, `bool`, `number`, `timestamp`,
  `url`, `enum` with values); the UI shows them as a panel. In a `status`
  answer, `in_use` feeds the release rating (6.1) and the hand-over
  confirmation; `foreign_holder` is drift (10.3).
- `actions`: name, title, `requires` (`holder`, `holder-or-sharee`,
  `reserve-group`, `admin`), a JSON Schema for the parameters (the UI
  builds a form from it; enums become choices), `result` (`none`, `text`,
  `url`, `secret-url`), a `rating` for MCP, and optionally `confirm` (a
  text the UI shows before running it).
- `events`: which events the adapter wants.

The core checks `requires` and validates `params` against the schema
before it calls `act`; the adapter checks again what it relies on. A
`secret-url` result goes to the caller only: never stored, never logged,
never in an event, never over MCP. The UI opens a `url` or `secret-url`
in a new window, or copies it.

`describe` is read at start and on `SIGHUP`. An adapter whose `describe`
fails is shown as broken and its actions disappear; the rest of the
server runs.

### 7.3 Events and the outbox

A change an adapter wants writes, in the same transaction as the change,
one outbox row per adapter. A worker per adapter takes rows in order per
resource, calls `event`, and marks them done, or retries exit 2 and
failures with backoff (`backon`) up to `adapter_retries` (default 5), then
shows "needs attention" on the resource page with a retry button for
administrators. The reservation itself is never rolled back because an
adapter failed: the register says who holds the resource; the adapter's
state says what it could do about it.

`status` is called when a resource page is opened and for the list at most
every `status_cache` seconds (default 15), at most `adapter_parallel`
calls at once (default 8).

### 7.4 What the UI, the API and MCP make of it

For each capability of a resource, the resource page shows a panel: the
status fields with their titles and types, and one button per action the
viewer may run (by `requires`); an action with parameters opens a form
built from its schema; a `confirm` text is asked first; the result is
shown, opened or copied by its kind. The same action is
`POST /api/v1/resources/<id>/actions/<capability>/<action>` and, unless
its result is secret, the MCP tool `place_<capability>_<action>`. Nothing
in the core, the templates or the API names a capability other than
`notice`.

## 8. `notice`: the host knows who holds it

`notice` is built in, not an adapter: there is nothing for an adapter to
do on the server. The host pulls, so the server's part is a read model
(what a host should show) and the host's part is `place host ...`.

### 8.1 How the host learns: pull

`place host sync` runs on the host as a systemd service, polls
`GET /api/v1/resources/<id>/notice` every `poll` seconds (default 30)
with its `host:<id>` token from `token_file` (0600 root), sends
`If-None-Match` with the last ETag, and writes
`/run/place/reservation.json` atomically (temp file in the same
directory, `0644 root:root`, rename) with the time of the last successful
fetch.

Pull, because:

- the server needs no credential on any host; a push needs an account on
  every host that the server can write through, and a taken-over server
  would hold all of them;
- it heals itself: a host that was off or rebooted (`/run` is a tmpfs),
  or a server that was down, is right again at the next poll, with no
  delivery queue and no reconciliation;
- the host already reaches the server's network; nothing has to reach
  into the host.

The cost is a lag of up to `poll` seconds after a change; the web UI says
so on a resource with `notice`.

The file is a read copy of the register, never a source of truth:

```json
{"schema_version": 1, "resource": "rt03", "fetched_at": "2026-11-19T10:00:00Z",
 "mode": "enforce", "exempt_groups": ["rt-admins"],
 "holders": [{"login": "user1", "name": "User One", "purpose": "latency tests",
              "since": "2026-11-19T08:00:00Z", "until": null}],
 "allowed_logins": ["user1", "user2"]}
```

`allowed_logins` is every holder, every sharee and every login an adapter
added to a reservation (`reservation_logins`, a shared desktop account).
`exempt_groups` are the resource's and the server's `admin_groups` plus
the capability's own `exempt_groups`.

**Server down or unreachable:** the file stays as it was and `fetched_at`
ages. After `stale_after` (default 15 minutes) the notice reads "state of
the reservation unknown since ...", and `enforce` falls back to `warn`: a
server outage must not lock people out of hosts. A host whose file was
never written behaves as free. The sync logs one line when it starts
failing and one when it recovers, not one per poll.

### 8.2 At login

PAM through `pam_exec`, reading only the local file:

- **Warn** (session phase), in the PAM service files named in
  `pam_services` (default `sshd`, `gdm-password`):
  `session optional pam_exec.so stdout quiet /usr/bin/place host notice`.
  For a login not in `allowed_logins` it prints: reserved by NAME (login)
  since ..., until ... or open-ended, purpose. sshd shows PAM info
  messages after login (as for `pam_motd`); GDM shows them on the
  greeter. Because a greeter message is easy to miss, an XDG autostart
  entry (`/etc/xdg/autostart/place-notice.desktop`) runs
  `place host notice --desktop`, which shows the same text as a desktop
  notification (`notify-rust`).
- **Enforce** (account phase, only when `mode` is `enforce`):
  `account requisite pam_exec.so quiet /usr/bin/place host gate`. It exits
  non-zero (login refused, the reason printed) when the resource is held,
  the file is fresh, `mode` is `enforce`, and `PAM_USER` is not root, not
  in `allowed_logins` and in none of `exempt_groups`. Every other case,
  including a missing, unreadable or stale file, exits 0. A holder whose
  `until` has passed counts as gone.

Installed into the named PAM service files only, never into a common
stack: `cron`, `sudo`, `su`, `systemd-user` and the console `login` must
not be gated, or a reservation would break a holder's cron jobs or an
administrator's console. The local console is the way in when everything
else is wrong. `place host install` / `uninstall` writes and removes
exactly these lines (marked with a comment), the autostart file, the
sync unit and `/run/place` through a `tmpfiles.d` line; provisioning may
do the same itself, and installs the token.

### 8.3 Lifecycle gates

Updates, reboots and driver repairs ask: is this resource reserved?

- **On the host** (what a play running over SSH uses):
  `place host busy` reads the local file. Exit 0: free, prints nothing.
  Exit 3: reserved, prints one line, "reserved by NAME (login) since ...:
  purpose". Exit 4: unknown (no file, or stale), prints why; `--fail-open`
  turns 4 into 0 for callers that must not stall on a dead server. Works
  with the server down.
- **From anywhere**: `place busy <id>` and
  `GET /api/v1/resources/<id>/busy` (a `read` token is enough), the same
  answers, for resources without `notice` and for a controller that asks
  for many (`place busy --label class=rt`).

For a DCV workstation a lifecycle action asks both: the seat probe of the
seat protocol (is a desktop in use; it keeps asking the host, never
place, seat protocol trap 11) and `place host busy` (is it reserved).

### 8.4 Reserving from the host

A person logged in on a host reserves it from there through the server;
the host never reserves on its own.

- `place reserve [--purpose TEXT] [--until TIME]` and `place release` on a
  host with a `[host]` configuration run `sudo -n /usr/bin/place host
  claim` / `unclaim` (one sudo rule, for the groups that may reserve
  there). The helper runs as root, takes the caller from `SUDO_UID` only
  (argv names no user; `SUDO_USER` must match, as the seat helpers do),
  reads the groups with `getgrouplist`, and sends the request with the
  host token: this resource, this login, these groups. The server applies
  3.3 to that person as to any other, and records the surface `host`.
- The provisioning product's own command for claiming a desktop seat, on
  a site with place, calls `place host claim` first and stops if it is
  refused. The seat protocol itself is unchanged.
- **Server unreachable: the claim is refused**, with a message saying so
  and naming the server. A local claim that the register does not know is
  what this rule exists to prevent, and a remote desktop needs the network
  anyway.
- The trust this takes: the server believes the host about who its
  calling user is. Root on the host could name anyone, but only for this
  host's resource, and root there can do anything on it anyway (5.5).
- After a successful claim the helper runs one `sync` at once, so the
  notice is right before the command returns.

## 9. Status sources

A resource's `status.query` is a PromQL instant query (a template, 3.4),
sent to `prometheus_url` with `reqwest`. No sample: `unknown`. A value of
0: `down`. Anything else: `up`. `status.facts` is a map of name → query
whose first sample's value or a named label is shown on the resource page
(dcv-manager's CPU and memory came this way; prefer attributes from the
import where the provisioning model has them). Cached `status_cache`
seconds, a 5-second timeout; Prometheus down shows `unknown` everywhere.

Status is shown, never decided on: a `down` resource can be reserved (the
holder may be about to repair it).

## 10. Adapter `dcv`: a desktop on a reserved workstation

### 10.1 The seat protocol, unchanged

The host side is the seat protocol as it stands: the reservation record
on the host, the claim and release helpers for a manager, the token
verifier, the metrics. The `dcv` adapter takes the manager's part in it
and changes nothing: same helper command lines, same outputs, same metric
names, same rule that a seat never expires. It reaches the helpers as the
manager does today, over SSH as the manager's account with a sudo rule
for the two server helpers (Kerberos or a restricted key, as the site has
it), through the system's OpenSSH client (crate `openssh`, so the site's
`ssh_config`, GSSAPI and known hosts apply). This is the one path from the
server to hosts, and only to hosts with the `dcv` capability. The paths
and the account the protocol leaves to the site are the adapter's
configuration, with no default that names anything.

The seat record on the host is the seat protocol's fact (who has a
desktop there), not a reservation: the register stays the one source of
truth for who holds the workstation.

### 10.2 What it declares

| Action | requires | params | result | Does |
|---|---|---|---|---|
| `start` | `holder-or-sharee` | `session` (enum from the resource's `dcv.sessions`), `as` (enum: the holder's login and `dcv.accounts`) | `none` | `ssh <manager>@<host> sudo -n <claim_helper> --user <login> --duration <token_ttl> --email <mail> --name <name> [--shared-with <mails>] [--session <s>]`; returns `reservation_logins` = `[as]` when `as` is a shared account |
| `connect` | `holder-or-sharee` | none | `secret-url` | the same claim again (the protocol mints a fresh token and keeps the session); the URL built from the helper's `host` and `token` as the protocol states (`#console` in the fragment) |
| `stop` | `holder` | none | `none` | `sudo -n <release_helper>`: the desktop ends, the reservation stays; `confirm` says unsaved work is lost |
| `adopt` | `admin` | none | `none` | shown only on drift; asks the core to adopt (10.3) |

Status fields: `desktop` (bool, a DCV session exists), `session_owner`
(text), `token_expires` (timestamp), `seat_holder` (text: whom the host's
record names). `in_use` is `desktop`. Status is read from the protocol's
metrics in Prometheus (metric names in the configuration), never by a
shell on the host.

Events: `released` (any reason) and `handed-over` run the release helper,
so the seat follows the reservation. A hand-over of a resource with a
running desktop ends the old holder's desktop (the UI's confirmation says
so when `in_use`), and the new holder starts their own.

- The desktop choice is `dcv.sessions` from the import: the provisioning
  model knows which desktops it installs. dcv-manager ran a shell loop
  over SSH to list them, which the protocol's sudo list does not cover.
- `--shared-with` gets the sharees' mails as last asserted (5.4), for the
  protocol's metrics.
- Each `connect` replaces the token on the host, so a link copied earlier
  stops working for new connections; the action's title says "new link".

### 10.3 Drift: a seat held past the register

A seat can be held on the host without a reservation: claimed with an old
seat helper that does not call `place host claim`, or claimed while the
server was down by a path that does not ask it. The adapter reports it as
`foreign_holder` (the seat's user, when that login is neither a holder
nor a reservation login). The resource page shows it as drift, and an
administrator has two actions:

- **adopt**: the core makes a reservation for that person (the operation
  `adopt` of 3.3, recorded as such), so the register is true again;
- **stop**: the release helper ends the seat.

Nothing happens to a drifted seat by itself: the adapter never releases a
seat the register did not ask for. A `start` for someone else on such a
host fails with the helper's reason (exit 1), which the UI shows.

Nothing of section 10 is in the core or the UI: they show a panel with
four fields and up to four buttons from `describe`.

## 11. Surfaces

### 11.1 HTTP API

JSON, `schema_version` in every body, one record type per object
(`resource`, `reservation`, `event`, `notice`, `status`, `adapter`,
`error`). Under `/api/v1/`:

| Method, path | What |
|---|---|
| `GET resources` | list, filters `kind`, `label`, `state` (`free`, `held`, `mine`, `retired`, `drift`) |
| `GET resources/<id>` | resource, open reservations, status, each adapter's status |
| `GET resources/<id>/history` | events, paged |
| `GET resources/<id>/notice`, `.../busy` | section 8 |
| `POST resources/<id>/reservations` | reserve (with a host token: `login` and `groups` in the body) |
| `PATCH reservations/<rid>` | extend, share, unshare, hand over |
| `DELETE reservations/<rid>` | release |
| `POST resources/<id>/adopt` | adopt (administrators) |
| `PUT resources/<id>/note` | |
| `POST resources/<id>/actions/<capability>/<action>` | an adapter action, generated from `describe` |
| `GET adapters` | every adapter's `describe`, for clients that build their own forms |
| `POST`/`PATCH`/`DELETE resources...` | virtual resources (source `ui`) |
| `PUT import/<source>` | section 4; `?check=true` |
| `GET events` | Server-Sent Events: every change, for the UI and scripts |
| `GET version`, `GET me` | |

Errors: `{"schema_version":1,"error":{"code":"held","message":...}}`, codes
from a closed list (`held`, `full`, `not-allowed`, `retired`,
`unknown-resource`, `invalid`, `adapter-refused`, `adapter-failed`).

Built on `axum` with `tower-http` (tracing, timeouts, body limits);
`tokio`; SSE with `axum::response::sse`.

### 11.2 Web UI

Server-rendered HTML (`askama`, templates and assets embedded with
`rust-embed`), live through the SSE stream with `htmx` and its SSE
extension (vendored, embedded); no build step for a frontend. If p-layer
settles its template question (its SPEC, open decisions) the other way,
place follows p-layer.

- **List**: cards per resource: name, kind, status, holder(s), purpose,
  since/until, note, links, a drift mark; filters; "mine" first.
- **Resource**: attributes, links, status facts, reservations with their
  actions (reserve with purpose and optional end, extend, share, hand
  over, release); a panel per capability (7.4); adapter state (pending,
  failed, needs attention); history.
- **Administration**: imports, adapters (`describe`, broken ones),
  tokens, virtual resources, drift, release of others' reservations (with
  a confirmation that names the holder).
- Times in the browser's time zone.

### 11.3 Command line

```
place list [--kind K] [--label k=v] [--free|--mine] [--format json]
place show <id>
place who <id>
place reserve <id> [--purpose TEXT] [--until TIME|--for DURATION]   # on a host: <id> optional, through place host claim
place extend <id> (--until TIME | --for DURATION | --open-ended)
place release <id> [--holder LOGIN]         # someone else's: administrators
place share <id> LOGIN... | place unshare <id> LOGIN...
place hand-over <id> LOGIN
place adopt <id>
place act <id> <capability> <action> [--param k=v]...
place busy <id>... | --label k=v
place import FILE [--check]
place resource add|edit|retire ...          # source ui
place token create|list|revoke ...
place serve
place adapter dcv <verb>                    # run by the server
place host sync | claim | unclaim | notice [--desktop] | gate | busy [--fail-open] | install | uninstall
```

`clap` (derive); times and durations parsed by `jiff` (`18:00`,
`2026-11-20T09:00`, `3h`, `2d`). On the server without `--server` the
command line talks to the local socket; with `--server URL` (or `server`
in the configuration) to the API with a `person` token from its
`token_file`; on a host with a `[host]` table, `reserve` and `release`
go through `place host claim` / `unclaim`. Exit codes: 0 done, 1 refused
(reason on stderr), 2 usage, 3 and 4 for `busy` (8.3).

## 12. Configuration and files

`/etc/p-lace.toml`, every key optional, defaults work for a server on
loopback behind a proxy on the same host (conventions). `toml` + `serde`.

```toml
[server]
listen = "127.0.0.1:8470"
socket = "/run/p-lace/place.sock"
database = "/var/lib/p-lace/place.db"
trusted_proxies = ["127.0.0.1/32", "::1/128"]
user_header = "Remote-User"        # groups_header, name_header, email_header
admin_groups = []
max_until = "90d"
mcp_listen = ""                     # off
prometheus_url = ""                 # no status

[links.workstation]
dashboard = "https://grafana.example.org/d/node?var-host={{ id }}"

[adapters.dcv]
command = ["/usr/bin/place", "adapter", "dcv"]
timeout = "60s"
ssh_user = ""                       # the seat protocol's manager account
claim_helper = ""
release_helper = ""
reservation_metric = ""
session_metric = ""
token_ttl = "8h"

[host]                              # on a host: read by place host ...
server = ""                         # https://place.example.org
token_file = "/etc/p-lace/host-token"
resource = ""                       # default: the short host name
poll = "30s"
stale_after = "15m"
pam_services = ["sshd", "gdm-password"]
```

- Database: SQLite through `rusqlite` (feature `bundled`), WAL mode, one
  writer task, migrations with `rusqlite_migration`. Backups are the
  site's (the file, or `place export`); losing it loses the register and
  the history; hosts keep their last copy and fall back to `warn`.
- The server runs as its own account under systemd
  (`contrib/p-lace.service`: `StateDirectory`, `RuntimeDirectory`,
  `ProtectSystem=strict`, `NoNewPrivileges`). Of the hosts it holds only
  the seat protocol's manager credentials, for the `dcv` adapter.
- On a host: the binary, `contrib/p-lace-host.service` for the sync
  (write access to `/run/place` only, the token readable by it), the host
  token (0600 root), the sudo rule for `claim` / `unclaim`, the PAM lines,
  the autostart file, `tmpfiles.d` for `/run/place`.
- Logging: `tracing` to the journal.

## 13. dcv-manager, feature by feature

| dcv-manager | In place | Where |
|---|---|---|
| OIDC login, session cookie, token refresh, logout | the auth proxy | outside |
| entitlement group checked at login and every request | `reserve_groups`, asserted per request | core |
| workstation list discovered from Prometheus `up` | the import | core |
| online / no DCV state | status source; `desktop` from the protocol's metrics | core, dcv |
| hardware from Prometheus (CPU, memory, GPU) | attributes from the import; `status.facts` where needed | core |
| live updates over WebSocket, 10 s heartbeat | SSE on every change | core |
| optimistic overlay (45 s) | not needed: the register is the truth for reservations; adapters show their own progress | - |
| reserve (claim helper at once) | reserve (core), then `start` (dcv) | core, dcv |
| desktop choice listed over SSH | `dcv.sessions` from the import | dcv |
| reserve as the shared account | `start` with `as` from `dcv.accounts` | dcv |
| connect (re-claim, connect URL) | `connect` | dcv |
| share by link | `connect`, copied | dcv |
| share with persons (`shared_with`) | sharees | core; passed on by dcv |
| release by the owner | release; seat released on the event | core, dcv |
| kick in debug mode, no server-side role | release of another's, administrators only, recorded | core |
| release of an unowned shared-account seat | drift: adopt or stop, administrators | dcv, core |
| per-host description, 200 chars | `note` | core |
| Grafana link from a build-time template | link templates per resource or per kind | core |
| `/api/version` | `GET /api/v1/version` | core |
| `descriptions.json`, `overlays.json` | SQLite | core |
| `trusted_networks` | `trusted_proxies` | core |
| in-process token store, `/auth/verify`, test token, log viewer | not ported (already unused or removed there) | - |

## 14. Tests

- Core: the operation table (3.3) as a matrix of person × groups ×
  resource state → done or the refusal code; capacity and "one place per
  person"; concurrent reserve from many tasks gives exactly `capacity`
  reservations; `until` releases with reason `ended`; adopt.
- Import: create, change, retire, un-retire; foreign id refused whole;
  unknown field, unknown capability and settings against the schema
  refused; `--check` writes nothing.
- Identity: headers from a trusted peer accepted, from another peer 400;
  no login 401; socket identity from a real `UnixStream` pair; tokens by
  scope, a host token refused for another resource and for any other
  route.
- Adapter contract, against fixture adapters written as shell scripts:
  each verb's input; exit codes 0, 1, 2, other; time limit kills the
  process group; oversized and non-JSON output; a broken `describe`;
  `requires` and parameter schema enforced before `act`; a `secret-url`
  in no event, log line or MCP tool list; outbox order and retry; the UI
  panel and form rendered from a fixture `describe`.
- Link templates: a label with `&`, `#`, quotes stays inside its
  parameter; a non-http result dropped.
- Host: `notice`, `gate`, `busy` against fixture files (free, held,
  holder, sharee, shared login, exempt group, root, passed `until`,
  stale, missing, warn and enforce); `sync` against a test server (ETag,
  server down, recovery logged once); `claim` takes the user from
  `SUDO_UID` only and refuses when the server is unreachable.
- `dcv`: against a fake `ssh` on `PATH` that records argv and answers
  like the helpers: exact argument lists, URL forms, release on every
  release reason and hand-over, drift reported and adopted.
- MCP: tools generated from `describe`, secret actions absent; the rating
  rules of 6.1; release of another refused without the administrator
  group. The shared service side is p-act's to test.

## Rejected alternatives

- **Pushing the notice to hosts** over SSH with a forced command: it puts
  a server credential on every host and needs reconciliation for reboots
  and missed pushes; pull needs neither (8.1).
- **Adapters as in-process Rust traits**: every new adapter is a rebuild
  and a release of place, a crashing or hanging adapter takes the server
  with it, and adapters are bound to Rust and to place's internal API.
- **Adapters as MCP servers** (a long-running process, `tools/list` as
  `describe`): a later option for adapters that keep a connection open;
  not now, because it brings back a process to supervise and a protocol
  session for what one exec does.
- **Local claims on a host without the server**, reconciled later: two
  registers that disagree is the problem dcv-manager's overlay and drift
  already had; a local claim goes through the server or is refused (8.4).

## Phases

1. **Core, import, web UI, local command line.** Resources,
   reservations, events, the operation table, link templates, the import
   with `--check`, virtual resources, the proxy entrance and the Unix
   socket, the web UI with SSE, `--format json`, tokens, `place busy`.
   Usable by itself as a visible register: "who is on rt03".
2. **Hosts.** Host tokens; `place host sync`, `notice` (warn, then
   enforce), `busy`, `claim` / `unclaim`; status sources.
3. **The adapter contract and `dcv`.** `describe`, `status`, `act`,
   events through the outbox, generic panels and forms; the `dcv`
   adapter, drift and adopt; the dcv-manager table complete. Run beside
   dcv-manager on a few workstations, then replace it.
4. **Agents.** The MCP service with tools generated from `describe`,
   once `probe serve` runs stage 1 and its service side is shared in
   `p-act`.

Later: person tokens for the command line elsewhere (needs the proxy rule
in 5.3); adapters as MCP servers; future bookings; telling logged-in users
when a reservation starts; asking the holder before an administrator's
release (approval system, section 9).

## Decided later (operator, 2026-11-19)

- **No future bookings for now.** No calendar in v1 or the phases above;
  `since` keeps room for a start in the future without a schema change.
- **The holder is not told when an exempt administrator logs in.** The
  exempt login is still warned at login like anyone else.

## Open questions

None at the moment.
