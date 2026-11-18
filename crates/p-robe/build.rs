//! Says, in the binaries and the tests of this package, which commit they were built from (`PROBE_BUILT_FROM`):
//! `git rev-parse --short=12 HEAD`, with `-dirty` when tracked files differ from it. A caller that sets the
//! variable itself (the Stage A and B scripts do) is believed. Without git and without the variable it is
//! `unknown`. The stage-1 tests print it and stop when the run expected another (`PROBE_EXPECT_BUILT_FROM`), so
//! that an old binary is never taken for the checkout's.

use std::path::Path;
use std::process::Command;

fn git(args: &[&str]) -> Option<String> {
    let out = Command::new("git").args(args).current_dir(env!("CARGO_MANIFEST_DIR")).output().ok()?;
    out.status.success().then(|| String::from_utf8_lossy(&out.stdout).trim().to_string())
}

fn main() {
    println!("cargo:rerun-if-env-changed=PROBE_BUILT_FROM");
    // Anything in the workspace may make the tree dirty, and a commit moves HEAD (in a worktree too).
    println!("cargo:rerun-if-changed=../../crates");
    println!("cargo:rerun-if-changed=../../Cargo.lock");
    if let Some(head) = git(&["rev-parse", "--git-path", "HEAD"]) {
        let head = Path::new(env!("CARGO_MANIFEST_DIR")).join(head);
        println!("cargo:rerun-if-changed={}", head.display());
    }
    let built = std::env::var("PROBE_BUILT_FROM").ok().filter(|v| !v.is_empty()).unwrap_or_else(|| {
        match git(&["rev-parse", "--short=12", "HEAD"]) {
            Some(commit) => {
                let dirty = git(&["status", "--porcelain", "--untracked-files=no"]).is_some_and(|s| !s.is_empty());
                if dirty { format!("{commit}-dirty") } else { commit }
            }
            None => "unknown".to_string(),
        }
    });
    println!("cargo:rustc-env=PROBE_BUILT_FROM={built}");
}
