# preserve: the daemon's socket protocol (proposal)

Status: accepted by the designer as the protocol to build on, with the answers of section 7 folded in. Not built yet. It follows the designer's decisions
(socket in a 0700 directory, peer read or dropped, one JSON object per line with `schema_version`,
request identifiers, progress as events) and the second set: **closing a connection cancels only what
was asked as bound to it; backup, prune, check and restore are the daemon's jobs.** It answers the ten
requirements of `crates/p-ledge/proposals/stage2-mac.md`, section 8.5, one by one (last section).

## 1. Transport

- **Socket**: `p-reserve.sock` in a directory made 0700 and owned by the daemon's user; the socket is
  0600 in it. Per-user daemon (workstation): `$XDG_RUNTIME_DIR/p-reserve/` on Linux,
  `~/Library/Application Support/p-reserve/` on macOS. Host daemon: `/run/p-reserve/`.
- **Peer**: read at accept with `p_act::peer::admit(&socket, &Policy::OwnUser)` (p-act with `default-features = false`,
  which pulls only libc); no copy. A peer whose credentials cannot be read is dropped, told nothing, and the throttled log line is p-act's. **A peer is served only if its uid is the
  daemon's own** (decided). Other uids, root included, are dropped; there is no operators' group. Reason: `restore` writes a path the
  client names (section 5); a root daemon serving another uid would be a way to write anywhere as root.
  So a host daemon is reached by the user it runs as (or by root if it runs as root).
  The protocol between this per-user daemon and the root helper that the macOS snapshot source needs is **not this
  one**, so "same uid only" does not cover it; that helper's protocol is its own document.
- **Framing**: one JSON object per line, UTF-8, `\n`. Reading uses `p_act::exchange::LineBuffer` (bounded,
  cancel-safe, shared with p-act) with its own limit: requests at most 64 KiB, answers and events at most
  1 MiB. A longer line ends the connection (`ExchangeError::LineTooLong`). Lists are paged (section 3), so no
  answer needs more.
- Every message has `schema_version` (integer, now 1) and `type`.

## 2. Messages

Client to daemon: `hello`, then requests. A request is `{"schema_version":1,"type":"<op>","id":"<client's string, at most 64 bytes>", ...args}`.
Daemon to client:

- `answer`: `{"type":"answer","id":..., "result":{...}}`. Exactly one per request, unless it is a job
  (section 4: the answer says `accepted` and carries the job).
- `error`: `{"type":"error","id":..., "code":"<code>", ...}`, in place of the answer. Codes are a closed
  list. Outcomes keep their names (`no-repository`, `locked`, `wrong-password`, `timed-out`, `failed`), plus
  `bad-request`, `unsupported`, `not-found`, `busy` (with the job that holds it), `too-large`,
  `refused` (a rule said no), `shutting-down`. An optional `detail` is the engine's own words **for a log, not for
  display**; it is cut to 512 bytes and passes the rule of every shown string in the workspace (no control
  characters, no bidirectional marks: p-act's `text::check`, which is not exported yet, so `p_reserve_core::text::for_display`
  states it again until it is).
- `event`: `{"type":"event","subscription":"<id>","seq":n,"topic":"...", ...}`.

Strictness. The daemon refuses a request with an unknown member, an unknown type, a wrong version or a
second object on a line (`bad-request`; the connection stays unless the line was too long). A client ignores
unknown members of answers and events. A change that adds a member or a value keeps `schema_version`; a
change that removes or reinterprets one bumps it.

`hello` (first message, from each side): the client says its name and `schema_version`; the daemon answers with its
`schema_version`, its version, and `can`: the list of what this daemon can do (`"browse"`, `"restore"`,
`"backup"`, `"prune"`, `"check"`, `"verify"`, `"excludes"`, `"schedule"`, `"jobs"`...). A front end hides what is not listed.
A version the daemon does not speak: `error unsupported`, then close.

## 3. Reading: state first, then events

- `status`: the whole present state in one answer: daemon, `can`, targets (name, whether reachable, open or not),
  declared pairs with their health (the `Health` of p-reserve-core: level, per pair freshness, last outcome,
  unreadable count, reasons as codes), running and recent jobs, the schedule, and `seq`, the number of the last
  event reflected in it.
- `health`: the same `Health` as `preserve health` (exit code included).
- `targets`, `sources`, `jobs`, `job {job}`: one list per noun.
- `subscribe {topics:[...]}`: topics `jobs`, `health`, `targets`, `schedule`. The answer carries the
  current `seq`; events after that carry `seq` increasing by one, so a client that asked for `status` ignores
  older events and notices a gap. **An event carries the whole changed object (a job, a pair's health), never a
  delta**, so no event is the only carrier of a fact and a client that missed one is right again after the next
  `status` or the next event about the same object.
- Browsing, bound to the connection:
  - `snapshots {target}`: snapshot id, time, host, paths, tags, and per snapshot what is known of its unreadable count.
  - `ls {target, snapshot, path, cursor?, limit?}`: `limit` at most 500; the answer has `entries`
    (name, kind, size, mtime) and `next` (a cursor or null). Answered from the open repository.
  - `read {target, snapshot, path, offset, length}`: at most 64 KiB, base64, for a preview. Pull, not push: a preview is
    a sequence of requests, nothing streams, and abandoning it needs no cancel.
  - `stat`, later `find`.

## 4. Jobs, and what closing a connection does

A **job** is a long operation the daemon owns: `backup`, `prune`, `check`, `verify`, `reprovision`, `restore`
(and, as nouns only, the exclude and schedule edits are not jobs: they are short requests).
`{"type":"restore","id":"1","target":"offsite","snapshot":"dbc721c9","paths":["/home/a"],"destination":"/tmp/out"}`
is answered at once with `{"type":"answer","id":"1","result":{"accepted":true,"job":"j-5f3a-17"}}`.

A job has an identifier (daemon-issued, unique across restarts through a boot component), a `kind`, its `target`/`source`, a `state`
(`queued`, `running`, `cancelling`, `finished`), when `finished` an `outcome` (an `Outcome` name; for a
cancelled job `cancelled`, which is a job result and not a ledger outcome: a cancelled backup does not touch the ledger)
and counts (bytes, files, unreadable). Progress is `event topic=job` with the whole job, at most a few per second.

| Operation | A connection closing | What ends it |
|---|---|---|
| `status`, `health`, listings, `snapshots`, `ls`, `read`, `stat` | the request is dropped (it is bound) | finishing, or closing |
| `subscribe`, `attach` | the subscription ends | `unsubscribe` or closing |
| backup (scheduled or asked), prune, check, verify, reprovision | **nothing**: the job goes on | finishing, or `cancel {job}` |
| restore | **nothing**: half a restore because a window closed is worse than one nobody watches | finishing, or `cancel {job}` |

- `jobs` lists running and recent jobs. The list is in memory (the last 100) and may be lost on restart. **One thing
  about a job is persisted: that it began.** Before a writing job (`backup`, `prune`, `check`, `reprovision`) starts, the
  daemon and the one-shot CLI alike write a start marker (`p_reserve_core::marker`: a 0600 file in a 0700 directory,
  locked for the life of the job). When the job ends, the ledger is saved and the marker removed. At the next start a
  marker nobody holds becomes, for each of its pairs, a ledger entry with outcome `failed` and cause `interrupted`
  (unless the ledger already records a run of that pair at or after the marker's start); a marker whose lock is held
  belongs to a running job and is left alone.
  `attach {job}` subscribes to one job and answers with its present state first, then events: a front end that
  connects later finds a running job and follows it.
- `cancel {job}` is the only thing that stops a job, from any connection; it answers at once, the job goes
  `cancelling`, then `finished` with `cancelled`. **`cancelled` means no snapshot was written, and it never touches the
  ledger.** A cancel is honoured up to the point where the engine saves the snapshot; if the snapshot exists, the job ends
  with its real outcome (`ok` or `incomplete`), the ledger is updated, and the job says the cancel came too late
  (`cancel_late: true`). A stored snapshot always updates the ledger. Data a cancelled run had already uploaded stays in the
  repository for the next run or the next prune. A cancel for a finished job is not an error: it answers with the
  finished state (idempotent); an unknown job is `not-found`.
- Exclusion: per repository one writing job at a time (`backup`, `prune`, `check`, `reprovision`); a second is `busy`
  and names the job that holds it. Restores and reads share. **When the schedule comes due for a pair while a job for that
  pair is running, whoever started it, the scheduled run is not queued and not recorded as a failure: the running job
  counts as that run.** Only if no job for the pair is running and the repository is held by another writing job is the
  scheduled run `deferred`, and tried again at the next tick. A repository's one pruning program (SPEC) is
  enforced by the daemon for its own jobs only.
- The daemon quitting stops its jobs (they are in-process); a restart lists none of them as running. What a job
  completed is in the repository and the ledger.

## 5. Paths and stores belong to the daemon

A restore `destination`, an exclude rule and a source are paths on the daemon's machine. A front end names them;
it does not read or write them. The exclude rules of a source, the prune marker and the schedule are
nouns the daemon owns; their names are proposed to the designer when their unit is built. Until they exist the daemon does
not list them in `can`, and no front end reads a file instead. A `restore` destination must be absolute and must
not exist unless `overwrite` is given; the daemon applies the same checks as the command line.

## 6. Section 8.5, one by one

| # | Requirement | Met |
|---|---|---|
| 1 | Everything a front end shows comes over the socket | Yes: state (`status`, lists), browsing, health, jobs. Excludes, prune marker, schedule are named as daemon-owned nouns (section 5), to be specified with their units; until then they are not offered, not read from files. The ledger file is read by `preserve health` for a host without daemon, which is the CLI, not a front end of the daemon. |
| 2 | State, then events | Yes: `status` with `seq`, whole objects in events, a gap is visible (section 3). |
| 3 | Codes and values, not sentences | Yes: error codes, outcome names, reasons as codes, freshness bands. `detail` exists for logs and is marked so. |
| 4 | No nouns of one platform | Yes: messages say `permission-missing {code}` or `snapshot-source-unavailable`, never FDA, Keychain, APFS or launchd; platform names stay in the seams. Open: where a front end needs the *name* of the thing to tell the user (the preflight code), codes are per meaning (`source-unreadable-by-policy`), and the front end words it for its platform. |
| 5 | A dialog is a message | Not applicable now: the daemon asks no question in v1 (the repository password comes from a file or the platform's secret store, not from a prompt; an SSH key approval is p-ledge's and p-act's). If a question is ever needed it follows p-ledge's shape (an event with an identifier, labelled fields, deadline, closed with a reason). |
| 6 | Long work: identifier, progress, cancel; closing cancels only what was asked that way | Yes: section 4 table. |
| 7 | Several front ends at once | Yes: events go to every subscriber; jobs are shared, and `attach` works for any number; `busy` names the holder. No question to answer once. |
| 8 | Nothing rests on a code signature alone | Yes: the peer is a uid, equal to the daemon's, and a socket in a 0700 directory; no signature is used. Nothing here widens anything beyond what that user can do himself; a root daemon is not reachable by another uid (section 1). |
| 9 | Older or newer front end | `schema_version`, refusal of unknown members in requests, tolerance in answers, `can` in `hello` and `status`. |
| 10 | Paths are the daemon's | Yes: section 5. |

## 7. Answers of the designer (all six accepted)

1. Same uid only; root and other uids dropped; no operators' group.
2. Job history in memory; the start marker is the one persisted thing (section 4).
3. `cancelled` = no snapshot was written; a late cancel ends with the real outcome (section 4).
4. Limits: progress at most 4 events per second per job, 1 MiB per line, requests 64 KiB, `ls` paged at 500, `read` pulled at 64 KiB.
5. Nouns for excludes, prune state and schedule: proposed when their unit is built.
6. `busy` naming the running job; a scheduled run that meets a running job for its pair counts that job as the run (section 4).
