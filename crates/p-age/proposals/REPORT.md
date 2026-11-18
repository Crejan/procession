# p-age report: the connections proposal

Branch `agent/p-age` (from `agent/p-act` 63c84b1). Only `crates/p-age/proposals/` changed. No code, no dependency added, `p-act` not touched.

## What exists

`approval-connections.md`: the two connections as a document, to become `doc/approval-connections.md`.

## What it fixes

- **Framing for both**: TLS 1.3, one JSON object per line, `v` and `type` on every message, lines at most 96 KiB, no HTTP.
- **The transport-independent part (section 3)**: `submit` (request bytes base64 + the service's signature) and `answer` (`approved` with approval and clearance | `declined` | `refused` with `by`, `reason`, optional `detail` | `expired`). It is meant to be the same as pledge's stage-1 `service.sock`; the clearance members are absent there. The service never acts on the word `approved`, only on verified approval and clearance.
- **The answer for "no"**: no signature; reason vocabulary for the broker (`bad-request`, `deadline`, `delegation`, `person`, `not-entitled`, `too-many-waiting`, `busy`), a seed list for pledge (for p-ledge to settle). The broker logs the code, never the `detail`, because pledge's detail may quote the request.
- **Service to broker**: one request per connection; no sign-in; resubmitting the same bytes after a break or a broker restart attaches to the held request; the queue is memory only.
- **Pledge to broker**: sign-in by an SSHSIG over a `connection` document (namespace `connection-v1@procession`, nonce and a TLS exporter value bound in); `ready`; then one signed `standing` (blocks, blocked keys, withdrawals, certificates, groups; full state each time; ordered by `(at, serial)`), then all waiting requests again. Replies: `approval`, `decline`, `refuse`. `delegation` carries the certificate and a proof signature by the agent key; `withdraw`. Ping every 30 s, silence is 90 s. Backoff 1 to 60 s.
- **Signers and verifiers (section 6)** with allowed-signers lines. The broker's `standing` has its own namespace `broker-v1@procession`, so it never verifies as a clearance; services' CA line must not list it.
- **Section 7** checks each message against the SPEC and the "Who checks what" table, and names the places where an implementation could be tempted to trust the broker: reading `approved`; clearance without approval; the broker logging "approved"; certificates or person names accepted because the standing was signed; skipping pledge's checks because the broker made them; groups in the standing used for decisions.
- **Dependencies (section 8)**: tokio, rustls 0.23 with the `ring` provider and TLS 1.3 only, tokio-rustls 0.26, rustls-pki-types, serde, serde_json, base64; dev: rcgen. No HTTP stack, no database, no mutual TLS. Everything resolves with `cargo generate-lockfile --offline` in a scratch directory (78 packages); **not built**, and `ring`'s C/asm build was not tried. Nothing is missing from the registry.

## What it leaves open, and why

Section 9 of the proposal, G1 to G12. The ones that need the designer: G2, G3, G5, G6. The ones for the other agents: `cancel` (G10), several devices (G9), reason codes of pledge. Values of the broker's limits (G12) are settings, not set here.

## Contradictions and gaps found

1. **Principals of the agent's certificate (G6).** `approvals.md` section 5: "the chosen groups as principals". `approval-formats.md` section 7 and `p-act` (`signature_person`): exactly one principal, the person. The broker needs the delegation's groups for R10. *Proposal*: principal = person; groups in a certificate extension signed by the delegation key.
2. **R5 against re-delivery (G2).** pledge signs for a call identifier once; a request delivered again after a lost connection would be refused as a replay and the lost approval cannot be remade (hardware keys are not reproducible). *Proposal*: pledge keeps its answer to each request until the deadline and resends it; R5 applies to a different request under the same identifier. Touches `p-ledge/SPEC.md` section 4 step 7 and R5.
3. **"No approval at all" (G3).** An approval that returns while the service's connection is down needs holding in memory until the service's `ack` or the deadline. *Proposal*: accept as the one exception, memory only. Touches what the broker is trusted for: to the designer.
4. **The SPEC's checks lack the deadline (G4).** The broker holds requests to the deadline, so it needs a bound. *Proposal*: check 0.
5. **"One trust anchor" (G5).** The site CA's SSH key cannot verify a TLS certificate. *Proposal*: two files, the CA key and a TLS root.
6. **Namespaces (G1).** `approvals.md` section 5 lists "connection" among namespaces; this adds `broker-v1` (one namespace for everything the broker says to a pledge, with `type` inside) and `delegation-v1`.
7. **`schema_version` or `v` (G11).** The brief says `schema_version`; the formats use `v`. Proposal uses `v`.
8. **Block "by key" (G7).** Needs the key fingerprint from a certificate inside a signature; `p-act`'s `Certificate` has none.
9. **SPEC: "signed in with that person's connection key"** does not say what is signed. Proposal as above (a document with nonce, TLS binding, time).
10. Fundament open points (groups from a directory, no scheduled roll-out): nothing depends on them. `groups` may be empty; an administrator's block reaches a connected pledge at once and a returning one at sign-in.

## What I need

- **p-act**: namespaces `Connection`, `Broker`, `Delegation`; parsers for `connection`, `standing` and the `submit`/`answer` messages (so that pledge, broker and service share one); the key fingerprint of a signature's certificate (G7); `looks_armoured` is already there.
- **p-ledge**: its list of refusal reasons; the proof signature over the delegation's certificate at issuing time (before the key is handed over); G2; whether it wants `cancel`; which part of its `service.sock` proposal differs from section 3.
- **p-robe**: that its one client speaks `submit` and `answer` and treats the answer as in section 3.
- **orchestrator**: the designer's answers to G2, G3, G5, G6; `approvals.md` section 5 names the new namespaces; the workspace dependency entries when building starts.

## Update after the designer's decisions (integration 47bb806, merged)

Followed in `approval-connections.md`:
- (a) every signature in a message is base64 of its armoured bytes (`sig`, `approval`, `clearance_sig`, `proof`); stated in section 1, examples changed.
- (b) G6 closed: person is the only principal, groups come from `groups@procession`; registration reads person, end and groups from the certificate, refuses a certificate that breaks formats 3.1, has no group list in the message; pledge's word on groups is never used.
- (c) Ed25519 and ECDSA P-256 only, also for the connection key.
- (A, B) the `groups` member of the standing comes from the separately refreshed part of the broker's data; nothing scheduled or cadence-dependent; "roll-out" wording removed. (C, D) the `not-entitled` reason is now the one test. (E) `<service>` is the type's name.
- (F) new message `carried` (section 5): the broker stores and sends, byte for byte, a document signed by the issuer (the hosts list, namespace `hosts-v1@procession`) and cannot alter it; pledge verifies against the site CA's line. Not used in stage 2. Open: the principal name under which pledge verifies it.
- Allowed-signers lines now show the two services' lines of formats section 7.
Still open (G6a): how group memberships reach the broker on a directory site, the issuer's name for the hosts list, how host keys reach a pledge before stage 3.
p-act's note: do not depend on its old `call_sig` handling; the broker decodes base64 before `looks_armoured`.

## Update after the reconciliation decisions (orchestrator, p-ledge's `service-sock.md`, p-robe's review)

`approval-connections.md` is now the home of the shared exchange; section 3 is it, section 2 lists what a transport decides, sections 4 and 5 are the two broker transports.
1. One `submit` (`request`, `request_sig`) on all three hops; the broker passes the service's bytes on unchanged. No `request` message type.
2. One `answer`: pledge's is the same bytes toward a service and toward the broker; the broker builds its own for the service and adds `clearance`, `clearance_sig` on `approved`. Clearance members are configuration: required (service, stage 2) or refused (stage 1, pledge, the broker reading pledge); never "if present". Separate `approval`/`decline`/`refuse` and `accepted` are gone.
3. Correlation by the request's hash; an `answer`/`cancel` for an unheld hash is ignored and logged (hash and time only).
4. `schema_version` on every unsigned message; `v` on signed documents (connection, standing, clearance). The documents' carrying members are `doc`/`doc_sig`.
5. `by` on `refused`/`expired`; no `detail` anywhere; closed lists, unknown to `unknown`. pledge's reasons are p-ledge's table (my "first set" removed); the broker's list stays. Broker rebuilds, never forwards.
6. `cancel` in the shared exchange; the broker passes it on to pledge. G10 closed.
7. Line 96 KiB on every transport; open requests per connection is a transport parameter (section 2 table: `service.sock` 16, service to broker 1, broker to pledge not limited by the connection).
8. G11 closed. G1, G2, G3, G4, G5, G8, G9 and the dependency choice remain marked open for the designer and owner.

Found while doing this:
- **A closed connection cancels on `service.sock` but must not at the broker.** A service that reconnects and resubmits the same bytes attaches to the held request; if the end of a connection cancelled, the resubmission would be a second request for one call identifier (R5). Section 2 makes it a transport parameter. p-ledge's text ("a connection that closes cancels all its open asks") is right for its transport and should say so.
- **pledge's reasons lack a code for a person or key blocked at the broker** (needed when a standing blocks while requests wait). Proposal: `blocked`. Asked of p-ledge.
- **Stored answers (G2)** now appear as a rule of the exchange (3.7): a repeated `submit` gets the same answer again.
- The broker's reason names (`deadline`, `delegation`, ...) differ from pledge's (`deadline-past`, `unknown-delegation`, ...) on purpose; `by` says whose list a code is from.

## Update after the designer's decisions on the proposal (integration f4a97a7, merged)

Document: followed, then read once from top to bottom.
- G2: pledge's answer is final to the deadline, from a store on disk (3.7): `approved`, `declined` and verdict refusals are answered again from it, passing conditions (`limit`, `muted`, `unavailable`, `blocked`) are not stored; a cancelled request is over; `call-used` for a different request under a used identifier; a declined call is not put again.
- G3: accepted, text and SPEC agree. G4: check 0. G5: two anchors, each for one purpose (section 8).
- G1: `delegation-v1` and the proof are gone. The broker reads and checks the certificate with p-act (issuer: the person's delegation key; section 3.1 rules; at most 24 h), registers it under the SHA-256 fingerprint of the agent's public key, from the sign-in alone; registering a known certificate changes nothing.
- G8: no clock anywhere in sign-in or standing. The standing carries the sign-in's `nonce` and a counter `n`; pledge accepts it only on its own connection and only with a higher `n`.
- Hosts list: carried unaltered (`carried`), verified by pledge with `hosts namespaces="hosts-v1@procession" <CA key>`; newest `at` wins, no expiry. `hosts` joins the names the CA never certifies.
- A service gets exact codes; no notice that a request was shown; the 60 s tolerance never extends a deadline (only the 10-minute bound). `blocked` joins pledge's list as a passing condition.
- Code: only the doc comment in `src/register.rs` (key is the SHA-256 fingerprint of the agent's public key).

Section 3 is written to be lifted as it stands (no G-numbers, no p-ledge references); transports are section 2's table, sections 4 and 5.

**Attack check of dropping the proof:** a holder of only the connection key can register a certificate it has seen (they are in every call), but such a certificate is already valid for whoever holds the agent key, and registering adds nothing the delegation key did not sign; it cannot make one. A withdrawn or ended delegation cannot be revived (register keeps the first entry). One case remains: an agent key and certificate exfiltrated before pledge registered it; the broker then learns of it from whoever registers it, and the certificate is valid anyway. I see no attack that needs a mechanism.

Needs from p-act (listed in section 9): the codec for section 3, the standing and connection documents, certificate reading and checking with its identifier, the fingerprint of the key behind a signature.

## Step 1 built: the two connections and a request passed through (integration 43d175d merged)

**What exists** (`crates/p-age`, 53 tests, clippy clean, `cargo fmt`): `site` (persons, hosts, keys from a JSON file), `register` (as before, plus accessors and a file snapshot), `core` (the state machine, no I/O: checks 0 to 3 and the limit, the queue in memory, the clearance, the standing, the log), `wire` (the broker's own messages: challenge, signin, ready, notice, ping, delegation, registered/not-registered, withdraw, ack; the connection and standing documents), `net` (both connections over any async byte stream, bounded line reader, bounded `ssh-keygen` work, TCP listeners with total and per-address limits, the deadline sweep), `tls` (TLS 1.3 only, `ring`, the sign-in's exporter), `config`, `log`, `crypto` (a trait; the real one runs `ssh-keygen`), and `page serve [--config FILE]`. The shared exchange is `p_act::exchange`; `submit`, `answer`, `cancel`, `error`, the reasons and the clearance policy are not written again. Dependencies are the lines approved, in `crates/p-age/Cargo.toml`, plus `ring` (random nonce), `serde`, `serde_json`, `base64`, `tempfile`, `thiserror` as p-act has them; `Cargo.lock` is updated offline.

**Verified, and how**
- 29 unit tests of `core` with a signature double: each check's reason and order, the limit (default five, a resubmission not counted), queue order, delivery at sign-in after `ready` and the standing, answers (approved with clearance, declined, pledge refusals, unknown reasons mapped, a broker reason in pledge's mouth not passed), late approval is `expired`, answer given once, cancel, deadline sweep, supersede, block and unblock with counters, withdrawals, the log (never "approved", no parameters), the register across a restart.
- 21 integration tests with **real keys and real `ssh-keygen`** (site CA, broker key certified as `broker`, host key certifying a service key `probe@a.example`, delegation key certifying an agent key with `groups@procession`, approval key certified `jan:confirmed`): the whole path, with the service verifying approval (`verify_approval` against the CA) and the clearance (`verify_clearance`, `covers`) itself; the standing verifies as `broker` in `broker-v1` and not as a clearance, nor a clearance as a standing; every sign-in failure is one `signin` error (wrong key, nonce, binding, person, namespace, not a sign-in); blocked after the signature verified; supersede; a request that waits for a pledge that is away and arrives after `ready` and the standing; a service that lost its connection submits the same bytes and gets the answer it missed, pledge not asked twice; deadlines with a test clock; cancel reaching pledge; reasons 0, 1, 2 each (past and too-far deadline, tolerance only on the bound ahead, uncertified service key, wrong service name, certificate of another delegation key, unregistered, certificate naming another person); unparsable request answered for the hash of its bytes; not base64 is an error; one request per connection; limits; answers for another person ignored and logged; registration from the certificate alone (wrong connection, forged issuer, 30 h, not yet valid, tampered signature, a certificate breaking formats 3.1, twice, kept across a restart); withdrawal; too long a line; timeouts (shortened); a pledge may not send `submit`.
- 3 tests of the same lines inside real TLS 1.3 over memory (`serve_tls`, the code the TCP listener runs): the exporter binding accepted, a binding from another connection refused, a wrong root and a wrong name refused.
- `ssh-keygen -L` does verify a certificate's signature (a flipped byte in signature or principal gives "incorrect signature"), checked by hand; the broker uses it to tell the certificate's issuer, since p-act reads but does not verify a bare certificate.

**Never run:** a TCP socket (the sandbox cannot bind): `net::listen`, `ConnLimits` per address, `page serve` itself, `ctrl_c`. Real durations of the timeouts (tests shorten them). A load of many connections. A real pledge or service (nobody has built the client side of these lines yet; the tests play them with `p_act` and `ssh-keygen`). Keys in a Secure Enclave. Blocking by key, R10, the administrator's verbs, `page load`, the `carried` message and renewals: **not built** (stage 3).

**Where p-act lacked what I needed (not changed there; `src/keygen.rs`, ~100 lines, marked "to move to p-act")**
1. Verify a signature by a *plain* key in a namespace (the sign-in's connection document, namespace `Connection` exists but nothing verifies with it).
2. Sign in a namespace with the broker's key (`Signer::sign` is private; the standing, `Namespace::Broker`).
3. The key that issued a bare certificate (registration: `agent_certificate` reads, does not verify the issuer).
4. A *non-blocking* bounded line reader: `exchange::LineReader` needs `std::io::Read`; the broker is async, so `net::Lines` (~40 lines, cancel-safe) reads lines and hands them to `Message::parse`. An incremental form (`push(&[u8]) -> lines`) would serve both.
5. The broker's own messages and the connection and standing documents are in `p-age::wire`, since only the broker and pledge use them; pledge needs the same, so they probably belong in `p-act` too.

**Where the documents left something out (reported, not settled)**
- **How the two kinds of connection are told apart.** SPEC says two kinds, both inbound. I used two listen addresses (`listen_services`, `listen_pledges`). A single port would need the service to say first what it is.
- **Configuration format.** The workspace convention is TOML (`/etc/<crate>.toml`); that needs the `toml` crate, not approved. JSON for now (`/etc/page.json`, site file JSON). The site file's format is mine until `page load` fixes one.
- **A certificate that cannot be read has no identifier.** `not-registered` carries the delegation's fingerprint; for a certificate breaking formats 3.1 there is none to name, so the broker sends `error malformed-line` and closes. Proposal: that stands, or `not-registered` gets a variant without `delegation`.
- **Restart.** The register (delegations until their end, blocks) is kept in `state_dir/register.json`, rewritten atomically on every change; the documents say the register is kept but not where or how. If it cannot be written the broker says so on standard error and goes on in memory.
- **`bad-request` submit and "the connection stays open"** (3.6) against one request per connection (section 4): the broker answers and closes. Proposal: section 4 wins on the broker's transports.
- **An answer that was refused at once is also held until `ack`** (an answer is an answer); nothing in the document says otherwise.
- **`withdrawn` in the standing** lists every withdrawn, unended delegation of the person, whoever withdrew it; the register does not record who.
- **An `answer` with a `result` pledge's side does not know** is ignored and logged, so the service waits for the deadline (document 3.6); the request stays held.
- **Ignored messages** (an answer, cancel or ack for a hash not held, or not held for the sender) are logged as `ignored:<type>` with host and service `-`: the document says "the hash and the time, nothing else".
- **Pledge and `ping`.** A pledge that signs in and is silent is closed after 90 s; the broker never pings.

**What I need**
- p-act: items 1 to 5 above, then `keygen.rs` goes away and `wire.rs` shrinks.
- p-ledge and p-robe: nothing yet; the lines they must speak to the broker are in `tests/common/mod.rs` as a working client.
- orchestrator: the designer on the open points above (two listen addresses, TOML, unreadable certificate, who restarts what); the owner on `toml`.

## The designer's five decisions built (integration a670ea4 merged)

62 tests (29 unit, 6 config, 24 connections, 3 TLS), clippy clean, `fmt`. `src/keygen.rs` is kept until p-act's API is merged.

1. **One address.** `net::serve_connection` reads the first line (within 10 s): `submit` is a service's, `hello` (exactly `{"schema_version":1,"type":"hello"}`) a pledge's and is answered with `challenge`; anything else, a `hello` with a member, a missing `schema_version`, JSON that is not an object, is `error malformed-line` and the end (a `hello` with another version: `unsupported-version`; silence: `timeout`). `Kind` is gone; `listen`/`serve_tls` take no kind; the configuration has `listen`, a list of addresses, all alike; limits are per peer address. Tests: seven wrong first messages, a hello with a member, version 2, not JSON, silence, a service and a pledge on the same address.
2. **Configuration.** JSON, unknown members refused, empty `listen` refused. `Config::read` and `Site::read` refuse a file that group or others can write, or whose owner is neither root nor the user running the broker (`src/perm.rs`; the user is found from a file the broker has just made, no new dependency). Tested with modes 666, 664, 646, 622 refused and 600, 640, 644, 400 accepted.
3. **Certificate that breaks 3.1: `error malformed-line`; `not-registered` for a well-formed one.** Checked what an unauthenticated peer can learn (test `an_unauthenticated_peer_learns_nothing…`): a stranger's request, whatever it names (unknown host, host key that never certified the service key, a plain uncertified key, a registered person's real delegation, an unregistered one, a person the site lacks), is always `bad-request`; a past deadline is `deadline` for everyone, before any signature. Before sign-in a pledge connection answers `signin` to everything that is JSON and not a sign-in (delegation, withdraw, nonsense). **Found and fixed:** a message of a type the broker does not know got `unknown-type`, a known one got `signin`, so the vocabulary of the protocol could be probed; before sign-in both are now `signin` (a line that is not JSON is still `malformed-line`). **Found and left, for you to judge:** (a) anyone who holds a request's bytes and the service's signature (they travel only inside TLS to the broker, pledge and the service) can submit them again and is handed the held answer, approval and clearance included, until the `ack` or the deadline; no sign-in exists on that connection to prevent it. The approval is useful only to the service whose request it signs, which accepts it once, as the SPEC says. (b) A certified service learns whether a person is enabled or blocked (`person`) and whether a delegation exists (`delegation`, one code for unknown, ended and withdrawn); an authenticated person's pledge learns whether its certificate was well-formed. Both are the agreed coarse classes, not more.
4. **register.json.** `v` member (1; a missing or other version, an unknown member, bad JSON: the broker does not start), the file must be 0600 and its directory 0700 (a directory that is not there is made 0700; one open to others is refused, as is a file others can read), written to a new 0600 file, flushed and renamed over the old one. `page serve` stops with the reason; it never starts on an empty register in place of one it cannot read. Tested. **Left open:** a file that is *missing* is a first start with an empty register, since the broker cannot tell it from deletion; the state directory's 0700 is the guard. A write that fails after start is reported on standard error and the broker goes on in memory.
5. **One request per connection**: already so; a `submit` whose request does not parse is answered `refused` `bad-request` for the hash and the connection closes.

Not run, as before: TCP (`listen`, the per-address limit, `page serve`), real timeout durations.

## The silence rule, and p-act's API in place of `keygen.rs` (integration b040280 merged)

- **The broker never speaks first.** A connection that sends nothing within 10 s, or begins a first line and does not finish it, is closed without a word. A first message that is neither `hello` nor `submit` (a `hello` with a member or another version, JSON that is not an object, a first line longer than 96 KiB) gets `error malformed-line` and nothing more, then the close. A pledge that has said `hello` and does not answer the challenge still gets `timeout`; a line that is too long after the first message still gets `line-too-long`. Tests: `a_connection_that_says_nothing_is_closed` (silence, an unfinished first line, a too long first line), `the_first_message_says_which_exchange_this_is` (version 2 hello now `malformed-line`).
- **`src/keygen.rs` is gone.** `crypto.rs` uses `p_act::sign::{verify_connection, sign_broker, verify_agent_certificate}`; the standing is signed with `Signer::certified` and `sign_broker`. The async reader `net::Lines` is built on `p_act::exchange::LineBuffer`; it keeps only the waiting (the 10 s for a begun line and the wait for a line to begin) and the reads. The tests sign sign-ins with `sign_connection`; the two negative tests that need a signature in another namespace use a small `raw_sign` helper in `tests/common` (p-act has no function that signs arbitrary bytes in a namespace of the caller's choosing, and should not).
- Nothing was missing from p-act's API. `wire.rs` stays until p-act has the connection document, the standing and the unsigned broker messages.
- 62 tests pass, clippy clean.

## Register: missing file, `page init`, failed writes (integration merged with the designer's three decisions)

71 tests (35 unit, 6 config, 26 connections, 3 TLS), clippy clean. The failing-write tests make the state directory 0500 and skip themselves if the user can write anyway (root); they ran here (non-root).

- **Missing register.json refuses the start**, like a damaged one (`StateError::Missing`); `page init [--config FILE]` makes the empty register (0600 in a 0700 directory, made if absent) and refuses if one exists (`StateError::Exists`). `Config::build` stops without a register. Tested.
- **Failed writes go by direction** (`core.rs`):
  - *Restricting* changes (block, withdraw, forgetting an ended registration at the sweep) are applied in memory first, always, then stored. `block_person` returns `Stored::Yes` or `Stored::No(why)`; `Broker::block_person` hands that to the caller (the administrator's verb, when it exists, prints "blocked and stored" or "blocked, NOT stored: <why>" and exits non-zero; that verb is stage 3 and not built).
  - *Permitting* changes (registering a new delegation, lifting a block) are applied, stored, and **undone if the write fails**; the caller gets the refusal (`unblock_person` returns `Err(why)`). Registering a certificate that is already known changes nothing and needs no write, so it still answers `registered` while degraded.
  - *Degraded*: the first failed write sets it, with a line on standard error; every later attempt is the whole write; every change tries it, and the sweep (once a second) tries it if the last try was a minute ago or more; a success ends the state with a line on standard error. `Core::degraded()` and `Broker::degraded()` give the reason (the "status output": there is no `status` verb yet, so there is only this accessor and standard error). Degraded, requests, answers, withdrawals and blocks go on from memory (tested).
- **What pledge is told, where the document does not cover it:**
  1. *A withdrawal from pledge that was not stored*: nothing. It is in force; pledge gets the `cancel` it always gets for a request waiting under it and no other message; the broker is degraded. The document has no message for "in force, not stored", so I added none.
  2. *A registration refused because the register cannot be written*: the document has no answer either (`not-registered` has no such reason, and its reasons are about the certificate). I used the nearest existing message, `error busy`, then the close; pledge can sign in again and register again later. **This is a choice I had to make and the designer should confirm it or give a reason code**; a new `not-registered` reason (say `unavailable`) would keep the connection open, which is kinder than a close.
- The standing is not re-sent when a change cannot be stored: it reflects memory, which is what is in force.
