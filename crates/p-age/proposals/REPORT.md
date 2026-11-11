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
