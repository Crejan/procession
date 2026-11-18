# SFTP trial (throwaway)

Not a workspace member, not built by `cargo build` at the workspace root.
Run outside the agent sandbox: `sh crates/p-reserve/trial/run-trial.sh` (all steps),
`... c` (only C, against the sshd the script starts), `... build` (only build C).
The script appends one line to the real `~/.ssh/known_hosts` for `[127.0.0.1]:22222`
and removes exactly that line on exit, also on Ctrl-C. It prints how to check.
The program is pinned to rustic_core =0.14.0 / rustic_backend =0.8.0 (a pair that belongs together: rustic_backend 0.8.0 depends on rustic_core 0.14) and its Cargo.lock is committed and used with --locked;
change both pins together or not at all.
Delete this directory once the trial is decided. Results: REPORT.md.
