# SFTP trial (throwaway)

Not a workspace member, not built by `cargo build` at the workspace root.
`run-trial.sh` was written in a sandbox that blocked crates.io and local ports; it has
never been run. Read it before running it: it appends one line to the real
`~/.ssh/known_hosts` for `[127.0.0.1]:22222` and removes it on exit.
Run `sh crates/p-reserve/trial/run-trial.sh` outside the sandbox. Delete this directory
once the trial is decided.
