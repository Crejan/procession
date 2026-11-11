//! `pledge`: holds SSH keys and decides who may use them. See `SPEC.md`.

fn main() -> std::process::ExitCode {
    p_ledge::cli::main(std::env::args().skip(1).collect())
}
