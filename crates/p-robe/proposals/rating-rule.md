# Rating a call lower by its parameters - a proposal

Status: a proposal for the orchestrator and the designer. No verb needs it
yet: until one does, every call has its verb's worst rating (`SPEC.md`).
`doc/approvals.md` R4 fixes the principle: where a call may be rated lower than
its action's worst case, the rule is **data beside the action, not code**; for
a path, a list of prefixes, matched after the path is resolved, with the file
opened once and that same open file used. This document gives the row format,
the one place the code reads it, and one problem the principle runs into
(section 5) that I cannot settle alone.

## 1. What a row says

Today a row of the table holds `rating`, the worst case over every argument
the verb accepts, and `args` (none or some). A row that may be rated lower gets
a list of **parameters**. Each parameter says what it looks like, and what its
value does to the rating. Everything else stays as it is.

```
verb  sys read
  rating  secret none none            # the worst case; derived, see 3
  floor   open   none none            # what a call with every parameter at its lowest costs
  param   path   (position 0, required)
          type  path, regular files and directories
          rate  by the longest matching prefix:
                  /proc/sys/        open    none none
                  /etc/ssh/         internal none none
                  /var/log/         internal none none
                  /etc/shadow       secret  none none     # exact path: no trailing slash
                  otherwise         secret  none none
  param   lines  (key "lines=", optional)
          type  number 1..10000
          rate  not at all           # it changes no rating
```

Types and what they contribute:

| `type` | Accepts | Contributes |
|---|---|---|
| `path` | an absolute path, no `NUL`, resolved as in section 2 | the rating of its longest matching prefix, or `otherwise` |
| `choice` | one of a fixed list of words | the rating written beside the word; a word not listed is not accepted (refused as an invalid call, not rated) |
| `number` | an integer in a range, optionally with `steps` (`up to 30: brief`, `up to 300: outage`) | the rating of the step it falls in; above the last step, not accepted |
| `plain` | a value matching a pattern (the argument class of `rules.rs` is the minimum) | nothing |

A parameter is found by **position** (`position n`) or by **key** (`key=` at
the first `=` of the token). A key may appear once. Missing optional
parameters contribute nothing. A parameter the row does not list is not
accepted: the row also replaces the bare `args: none | some` as what decides
"arguments the verb accepts" (`SPEC.md`, "What the service does with a call",
step 1). Values come from the call's `params`, which are strings
(`approval-formats.md` section 3), so nothing in the formats changes.

**The rating of a call** is the worst, on each scale, of the row's `floor` and
every parameter's contribution (`Rating::worst_of`). Nothing else enters. A
call is never rated higher than the row's `rating` (section 3 makes this a
test), and where no rule applies the contribution is the parameter's
`otherwise`, which for a `path` is at least as bad as any listed prefix.
**What cannot be rated is rated at the top** (the rule of R4): a path that
cannot be resolved, a file that is not a regular file or a directory, a value
the table has no entry for.

## 2. A path: resolve, open once, use that

For a `path` parameter, in this order, by one function that both the service
and the dispatcher call:

1. The value is absolute, has no `NUL`, and is at most 512 bytes (the token
   class already excludes spaces and control characters).
2. **Open it:** `open(path, O_RDONLY | O_CLOEXEC | O_NOCTTY | O_NONBLOCK)`,
   following links (the ones the person's own login would follow). No other
   look at the path before this: no `stat`, no `access`, no `realpath` first.
3. `fstat` the descriptor. A regular file or a directory only; a FIFO, a
   socket, a character or block device is refused (reading it can block or
   act: `O_NONBLOCK` only keeps the open itself from hanging). Never rated, no
   contribution: refused as an invalid call.
4. **The resolved path of what is open:** on Linux `readlink` of
   `/proc/self/fd/<n>`. It names the file the descriptor holds, with every
   link and `..` already resolved by the kernel, not by us.
5. **Cross-check:** `stat` that resolved path and compare device and inode with
   the descriptor's. A difference means the name moved between steps 2 and 4:
   rate at the top.
6. **Match the resolved path against the prefixes by whole components.**
   `/etc/ssh/` matches `/etc/ssh/sshd_config` and `/etc/ssh`, never
   `/etc/sshd_evil`. An entry without a trailing slash is an exact path.
   **The longest matching entry wins**, so a narrow entry can raise
   (`/etc/shadow` inside `/etc/`) and can lower (`/etc/ssl/certs/` inside
   `/etc/`). Entries are unique, so there are no ties (a test). No match:
   `otherwise`.
7. **The verb reads the descriptor from step 2**, not the path again. In-process
   it reads the `File`; handed to a tool it is handed as `/dev/fd/<n>` with the
   descriptor kept open for the child. What was rated is what is read, because
   it is the same open file.

Directories: a listing reveals the names in the directory, and nothing about
the files in them. It is rated by the directory's own resolved path, like a
file. Reading a file inside is another call with its own path.

The prefixes are matched against the **resolved** path, so a link from an
open place to a secret one is rated by where it leads: `/var/log/x` pointing
to `/etc/shadow` is rated `/etc/shadow`. A link the other way (from a closed
place to an open one) is rated by the open place, which is right: it is the
content that is read.

Not Linux: `readlink` of `/proc/self/fd` is Linux. On macOS, where p-robe is
only built and tested, `fcntl(F_GETPATH)` does the same for step 4. The target
is Linux; the macOS path exists so that the tests run here, and anything the
tests show of step 4 is shown for `F_GETPATH`, not for `/proc`.

## 3. Where the data lives, and what keeps it honest

The rows stay in `src/table.rs` as typed constants (the data of this document
in the shape of Rust values: a `&'static [Param]` beside each `Verb`). No
configuration file: the table is the part of the service that must not be
edited by whoever can edit the host, because the ratings are the service's
word (`approvals.md` R4: "Rating is the service's responsibility"). One generic
function, `rate(row, params) -> Result<Rating, NotAccepted>`, is the only code
that reads a row's parameter rules. Adding a rule for a verb is a change to
the table and to its tests, not to that function.

Tests that keep a row honest (they run over the whole table):

- the row's `rating` equals the worst of its `floor` and every parameter's
  worst contribution (the declared worst case is derived and asserted, so it
  can drift in neither direction);
- `floor` is at or below `rating`; every contribution is at or below `rating`;
- no two prefixes of a `path` parameter are equal; every prefix is absolute,
  normalised, and has no `..`;
- `otherwise` of a `path` is at least as bad as every listed prefix **unless
  the row says so on purpose** (a verb that lowers everything outside a list
  needs the designer's eye; the default is the strict form);
- for `path` with temporary directories: component boundaries; a link out of
  a prefix; a link into one; a `..` that escapes; a name that moves between
  open and cross-check (simulated by a second thread); a FIFO and a device
  refused.

## 4. Where it is called

- **The service**, when it rates a call (step 2 of its list). It rates, as an
  unprivileged account, what it can: the resolved path through `realpath`
  needs search permission on directories only. Where it cannot resolve
  (permission denied), it rates the `path` at `otherwise`, which is the safe
  direction and means the person is asked about more than strictly needed.
  The rating goes into the request, and the person's approval is for that.
- **The dispatcher**, before it runs (section 5).

Both call `rate`. The catalogue prints the row's `rating` (the worst case) and,
for each parameter, its entries, so that a person can read what an agent is
asked about.

## 5. The problem: who opens the file

The principle says: open once, use that open file. The service and the
dispatcher are different programs under different accounts. The service (an
unprivileged account) rates; the dispatcher (root, through the same sudo rule a
person's call uses) reads. Two things follow.

- **A descriptor cannot be handed from the service to the dispatcher.** sudo
  closes every descriptor above 2 before it runs the command (`closefrom`),
  and the file may not be readable to the service anyway.
- So the file the service rated and the file the dispatcher reads are opened
  twice, in two places, and what was rated is not what is read: a path that is
  rated `/var/log/x` can be a link to `/etc/shadow` by the time root opens it.

**Proposal.** The dispatcher re-does the rating itself, and the approved
rating becomes a limit on it, never a licence:

```
sudo -n probe --within <exposure>,<damage>,<disruption> <noun> <verb> [args]
```

The dispatcher opens (section 2), rates with `rate`, and refuses (exit 64,
audit line `event=refused reason=above-approved`) if its own rating exceeds
`--within` on any scale. Then it uses the descriptor it holds. `--within` can
only lower what runs; it cannot make anything run that the table would not
allow, so a person who passes it, or leaves it out, gains nothing and loses
nothing (a person has the dispatcher under their own sudo rule and needs no
approval). The service always passes the rating of the request that was
approved. The two ratings may differ, in either direction, only because a file
moved: the dispatcher's wins when it is lower (the person approved more than
was needed), and a higher one stops the call. Race-free in the direction that
matters.

What this needs, beyond this crate:

- the dispatcher gets a second form that starts with `--` (the rule "no token
  starts with `-`" is about arguments; this is not one, and it is parsed
  before them, only in this position);
- the site's sudo rule for the service's account names `probe --within *`
  and the table's rows, which is a wider pattern than a person's rule. The
  derivation of the sudo rule from the table (`SPEC.md`) must therefore produce
  both forms, and say that the first is for the service's account only. This
  is the designer's to accept, because it touches what sudo allows.

If the designer does not want a flag, the alternative is that the **service
runs as root** for the rated read, which gives up the idea that the service
needs no access to anything. I advise against it.

## Open

1. The flag above, and the sudo rule it needs.
2. Whether the cross-check of step 5 is enough, or the verb should be refused
   altogether where the resolved path of the descriptor is not under a
   directory that only root can write (the prefixes protect against a link
   only if nobody unprivileged can put a link into the open places; `/tmp` is
   such a place and should be `secret` or absent from the lists).
3. Where the lines between `open`, `internal` and `secret` run for the first
   real path verbs (`approvals.md` section 10, open). The prefixes in section
   1 are an illustration of the format, not a proposal for the ratings.
4. `type pid` (a process: its command line is `internal`, its memory is
   `secret`) and others will want to be added when `rt procs` gets parameters.
   They are new `type`s in the table and in `rate`, nothing in the formats.
