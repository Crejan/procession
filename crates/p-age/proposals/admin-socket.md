# Proposal: how the administrator's verbs reach the running broker

Status: a proposal by the p-age agent, for the designer. Terms are those of
`doc/approvals.md` section 1. The verbs are `page block`, `page unblock`,
`page withdraw` and `page status`; `page load` and check 4 are stage 3 and
not touched. What is built does not depend on the open points at the end
(section 7); where it would, the code takes the proposal's choice and says so.

## 1. Why a socket, and why not the file

The verbs must obey the failed-write rule (`SPEC.md`, "What it keeps"): a
restricting verb takes effect in memory at once and says whether it is
stored; a permitting one is refused while the register cannot be written.
That rule lives in the running broker (it owns the register, the connected
pledges and the held requests). A verb that edited `register.json` itself
would have to repeat the rule, would not reach the memory of the broker that
is running (a block would take effect at the next restart), and would race
the broker's own writes. So the verbs are clients of the running broker.

## 2. The channel

A Unix stream socket `admin.sock` **in the state directory** (the directory
that holds `register.json`: 0700, owned by the broker's user).

- Made by `page serve` after the register is read, mode 0600 set
  explicitly after `bind` (not left to the umask). A socket that is already
  there is removed only if nothing answers on it; if something answers,
  `page serve` refuses to start ("another broker runs").
- **Who may connect**: the directory is already closed to everyone but the
  broker's user and root. In addition the broker checks the peer's user id
  (`SO_PEERCRED`/`LOCAL_PEERCRED`, tokio's `peer_cred`): it must be root or
  the user that owns the state directory (the broker's own). Anything else is
  closed without a word, **and so is a peer whose credentials cannot be read**:
  the rule for every socket is that an unreadable peer is dropped and told
  nothing (`admin::peer_allowed`, tested with an `Err`). Neither check relies on
  the other.
- **One command per connection**: one JSON line in, one JSON line out, then
  the broker closes. A line is at most 4 KiB; a command must arrive within 10
  s. The framing is the exchange's (`schema_version` 1, `type`, unknown
  members refused, lines ended by `\n`); codes are closed lists and an unknown
  one is never passed on.
- The verbs find the socket from the configuration file (`--config FILE`,
  default `/etc/page.json`: `state_dir` plus `admin.sock`), read as every
  settings file is. No second configuration.

## 3. Commands and answers

```json
{"schema_version":1,"type":"status"}
{"schema_version":1,"type":"block","person":"jan"}
{"schema_version":1,"type":"block","key":"SHA256:..."}
{"schema_version":1,"type":"unblock","person":"jan"}
{"schema_version":1,"type":"unblock","key":"SHA256:..."}
{"schema_version":1,"type":"withdraw","delegation":"SHA256:..."}
```

Exactly one of `person` and `key` is present. A key is the SHA-256
fingerprint as `ssh-keygen -l` prints it.

Answers:

```json
{"schema_version":1,"type":"done","stored":true}
{"schema_version":1,"type":"done","stored":false,"why":"permission-denied"}
{"schema_version":1,"type":"refused","reason":"unavailable","why":"read-only"}
{"schema_version":1,"type":"refused","reason":"unknown-person"}
{"schema_version":1,"type":"status","degraded":false,...}
```

- `done`: a **restricting** command (block, withdraw) is in force. `stored`
  says whether it is also written; if not, `why` is the reason, from a closed
  list: `permission-denied`, `read-only`, `no-space`, `io`. The text of the
  operating system's error goes to the broker's standard error, not into the
  answer.
- `refused`: nothing was done. `reason`: `unknown-person`, `unknown-key`,
  `unknown-delegation` (the administrator is trusted and told, unlike a
  pledge, who is answered alike for unknown and foreign), `unavailable` (a
  **permitting** command, unblock, while the register cannot be written; `why`
  as above), `malformed` (the command is not understood).
- The verbs print and exit:

| Answer | Output | Exit |
|---|---|---|
| `done`, `stored: true` | `blocked and stored: <what>` (`unblocked and stored`, `withdrawn and stored`) | 0 |
| `done`, `stored: false` | `blocked, NOT stored: <why>` | 4 |
| `refused` | `unblock refused: <reason>` | 1 |
| usage | | 2 |
| cannot reach the broker | `page: no broker answers at <path>` | 3 |
| `status`, degraded | the status | 5 |
| `status`, an enabled person has no valid certificate for a purpose | the status | 6 |

(One meaning each: 0 done, 1 refused, 2 usage, 3 no broker, 4 in force but NOT
stored, 5 degraded, 6 an enabled person without a valid certificate, 5 and 6 `status` only; each verb's `--help` prints the table.)

An unblock of a person or key that is not blocked is `done`, `stored` as the
write goes (it is idempotent, as a repeated withdrawal is).

## 4. What a block does, and what the connected pledges are told

- **Block a person.** As built: requests waiting for the person are refused
  `person`; their delegations stop at check 2/3; a connected pledge gets a new
  `standing` (counter +1) with `blocked: true`. Lifting sends one with
  `blocked: false`.
- **Block a key** (`SPEC.md`: "no request is passed to a pledge that signed in
  with it, and no approval by it is given a clearance"). A key can be one of a
  person's four keys, or an agent's key:
  - the person's **connection key**: a pledge that signs in with it is refused
    `blocked` (after the signature verified, as for a blocked person); one
    connected with it is told `error blocked` and closed, and its requests keep
    waiting;
  - an **approval key**: an approval whose signature is by that key is not
    given a clearance (the key is read from the certificate inside the
    signature, as for the person's name, without verifying); the service gets
    `refused` `person`;
  - the person's **delegation key**: every call under its certificates is
    refused `delegation` at check 2;
  - an **agent's key** (a delegation's identifier): the same as withdrawing it,
    and registering it is refused `blocked`.
  The standing's `blocked_keys` lists the blocked keys among *that person's*
  keys, so that their pledge stops signing with an approval key at once.
- **Withdraw** by an administrator ends the delegation at the broker, refuses
  what waits under it, and appears in the standing's `withdrawn` of a connected
  pledge, which is sent anew.

## 5. `page status`

One answer:

```json
{"schema_version":1,"type":"status","degraded":true,"why":"permission-denied",
 "pledges":2,"held":5,"delegations":7,"withdrawn":1,
 "blocked_persons":["eva"],"blocked_keys":["SHA256:..."]}
```

`degraded` and `why` are the broker's state (`SPEC.md`: from the first failed
write until one succeeds). The numbers and lists are what the register and the
queue hold. The verb prints them one per line and exits 5 when degraded, 0
otherwise, so a monitor can use it. Nothing about requests (hosts, services,
parameters) is in it: that is the log's.

## 6. What it does not do

No `page delegations` list yet (the administrator learns an identifier from
the log or the person; a list is a second command of the same shape and can be
added); no change of the site's data (stage 3); no command over TCP.

## 7. Open, each with the proposal built

1. **Where the socket is.** The state directory (it is private already, the
   broker is the only writer there). An alternative is `/run/page/`; the choice
   changes one path.
2. **Who may connect.** Root and the broker's own user. A group of
   administrators would need a setting; none is built.
3. **Blocking a key needs to know whose keys they are.** The site file gains
   optional members `confirmed_key` and `automatic_key` (public keys, plain
   lines) beside `connection_key` and `delegation_key`: the person's "four
   keys" of `SPEC.md`, so that the standing can list *their* blocked keys and a
   typo (`unknown-key`) can be told. Without them only the connection and
   delegation keys and registered agent keys could be blocked.
4. **`unknown-person`/`unknown-key` are refusals**, so that a typo does not
   "block" nothing. A person who left the site file but still has registered
   delegations can still be blocked.
5. **One command per connection** keeps a verb from holding the broker's
   attention; a monitor that polls `status` reconnects each time.
6. **The register file gains `blocked_keys`** (a member the reader of the
   previous version did not have; `v` stays 1 and a missing member is empty).
7. **Where the peer lookup lives: it should move to `p-act`, for pledge and
   page to share.** Today p-ledge has its own (`peer.rs`: `SO_PEERCRED` on
   Linux, `getpeereid` and `LOCAL_PEERPID` elsewhere, with `unsafe`) and p-age
   uses tokio's `UnixStream::peer_cred` (the same two system calls, no `unsafe`
   of ours, uid only). Two lookups mean two places for the rule "unreadable is
   dropped" and two answers if the platforms differ. *Proposal:* `p_act::peer`
   with `Peer { uid, pid }`, `peer(&impl AsRawFd) -> io::Result<Peer>` (what
   p-ledge has, behind the `libc` feature p-act already has), `own_euid()`, and
   the one decision function that p-age's `peer_allowed` is now:
   `admitted(io::Result<Peer>, allowed_uids) -> bool`, `false` on `Err`. p-age
   would call it on `stream.as_raw_fd()` and drop tokio's lookup; p-ledge would
   keep `Seen` (the program path, which only pledge reads) on top. Until then
   p-age's check is the one function `peer_allowed`, so the move is a change of
   one call. The broker's own user is today the owner of the socket it made;
   `own_euid()` would replace that.
