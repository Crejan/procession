# SFTP trial (throwaway)

Not a workspace member, not built by `cargo build` at the workspace root.
Run outside the agent sandbox: `sh crates/p-reserve/trial/run-trial.sh` (all steps),
`... c` (only C, against the sshd the script starts), `... build` (only build C).
The script appends one line to the real `~/.ssh/known_hosts` for `[127.0.0.1]:22222`
and removes exactly that line on exit, also on Ctrl-C. It prints how to check.
The program is pinned to rustic_core =0.13.0 / rustic_backend =0.7.0 in its Cargo.toml;
the registry now also holds 0.14.0 / 0.8.0 (change the pins to try those).
Delete this directory once the trial is decided. Results: REPORT.md.
