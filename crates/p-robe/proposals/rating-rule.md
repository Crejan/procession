# Rating a call lower by its parameters - a proposal

Status: **accepted by the designer, and implemented** in `src/rate.rs` and
`src/table.rs` (a verb with parameters), `src/dispatch.rs` (`--within`). The
decisions that changed this text are marked *(decided)*. No production verb has
parameter rules yet: until one does, every call has its verb's worst rating
(`SPEC.md`). The test verb `test read` (test builds only) exercises all of it.
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
7. *(decided)* **Nothing is rated lower under a directory that anyone but its
   owner or root can write.** A group or other write bit on a directory
   counts. The directories looked at are those the entry vouches for: from the
   directory a prefix names (for an exact entry: the file's parent) down to the
   file's parent, and the file itself if it is a directory. If one is writable
   by others, or cannot be looked at, the call keeps the **row's worst
   rating**, not just the parameter's `otherwise`. Above the entry nothing is
   checked: a link planted there changes where the path resolves, and the
   resolved path is what was matched. Access lists are not looked at.
8. **The verb reads the descriptor from step 2**, not the path again. In-process
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

*(Implemented as `Mode::Open` for the dispatcher and `Mode::Name` for the
service: the service, an unprivileged account, resolves with `realpath` and
`stat`, which need search permission on directories and not read permission
on the file, and keeps nothing open. The two modes share steps 1, 3 and 6 to
8; the cross-check and the descriptor are `Mode::Open` only.)*

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

## 5. Who opens the file *(decided: `--within`)*

The service (an unprivileged account) rates; the dispatcher (root, through
sudo) reads. A descriptor cannot be handed over: sudo closes every descriptor
above 2. So the dispatcher rates again, itself, at the point where it opens
the file, and the approved rating is a limit on it, never a licence:

```
sudo -n probe --within <exposure>,<damage>,<disruption> <noun> <verb> [args]
```

- The dispatcher opens (section 2), rates with `rate` (`Mode::Open`), and
  refuses (exit 64, audit line `event=refused reason=above-approved: rated
  ... against approved ...`, nothing runs, no start line) if its rating is above
  `--within` on any scale. Then it runs with the descriptors it holds.
- `--within` is read before the noun, in that place only (`dispatch::admit`);
  anywhere else it is an argument, and an argument may not start with `-`. A
  malformed rating is refused.
- It can only restrict. A person at the dispatcher leaves it out and needs no
  approval; the service always passes the rating of the request that was
  approved. A call the table refuses (`run command`), or that cannot run here,
  is not made to run by it.
- Because the service's account may call `probe --within *`, it can run
  **every verb** of the table through that sudo rule; what holds it back is the
  service's own checks, not sudo (`SPEC.md` says so).
- Order in the dispatcher: the pure checks, then the rating (this is where the
  files are opened; opening has no effect), then the lock, the start line, the
  verb. A call refused by `--within` therefore leaves one `refused` line.

Tested, in `rate.rs` and end to end in `tests/cli.rs` with `test read`: a link
planted between the service's rating and the dispatcher's opening (the second
rating sees where it leads and the call is refused); `..` out of a prefix; a
directory with a group or other write bit under an entry; the entry directory
itself; a FIFO; a missing file; a relative path.

## Open

1. Where the lines between `open`, `internal` and `secret` run for the first
   real path verbs (`approvals.md` section 10, open). The prefixes in section 1
   are an illustration of the format, not a proposal for the ratings.
2. `type pid` (a process: its command line is `internal`, its memory is
   `secret`) and others will want to be added when `rt procs` gets parameters.
   They are new `type`s in the table and in `rate`, nothing in the formats.
3. **Not verified on Linux.** `readlink /proc/self/fd/<n>` (step 4) is
   Linux-only and written but never run; the tests ran on macOS with
   `fcntl(F_GETPATH)`. The unit tests of step 5, the cross-check, pass there.
   Also unrun: the behaviour on a Linux file that was deleted (`readlink`
   gives a name ending in ` (deleted)`; the cross-check then fails and the call
   is rated at the row's worst, which is the intended direction).
4. **Access lists** and mount options (a `noexec`-like or read-only view)
   are not looked at by the writable-directory rule.
