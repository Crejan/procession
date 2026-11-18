# Captured ethtool output

Real output of `ethtool` from a host with a real NIC, one directory per
ethtool version (`6.1/`, `6.7/`, ...). The test `tests/ethtool_captures.rs`
reads every directory here. File names, for NIC `eth0`:

    -i.txt            from  ethtool -i eth0
    -S.txt            from  ethtool -S eth0
    --json_-S.txt     from  ethtool --json -S eth0      (spaces become _)
    -g.txt  --json_-g.txt  -c.txt  --json_-c.txt  -l.txt  --json_-l.txt
    --show-eee.txt  --json_--show-eee.txt  -k.txt  --json_-k.txt

Next to each, `<name>.code` holds the exit code (one number, no newline needed)
and `<name>.err` the standard error, when either is not empty/zero. Collect all with the loop in
`proposals/RUNBOOK-phase2-linux.md`.
