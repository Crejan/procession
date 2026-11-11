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
