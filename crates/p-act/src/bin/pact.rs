//! `pact`: the agent's signer. See `proposals/pact.md`.
//!
//! `pact serve --socket PATH` reads the bundle from standard input and serves MCP on a Unix socket;
//! `pact stdio --socket PATH` is the model's client's stdio server, a shim to that socket;
//! `pact call TOOL ARGUMENTS` and `pact tools` read the bundle from standard input and do one thing.
//!
//! This build has no HTTP client yet: every service is `unavailable` until that module is added.

fn main() {
    std::process::exit(p_act::pact::cli::run(std::env::args().skip(1).collect()));
}
