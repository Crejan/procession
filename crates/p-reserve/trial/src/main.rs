//! SFTP trial: open, list snapshots, list a directory, restore one file.
//! UNCOMPILED: written against rustic_core 0.13.0 from its examples/ls and
//! examples/restore; it could not be built in the sandbox (crates.io 403).
//!
//! Env: TRIAL_ENDPOINT (ssh://user@host:port), TRIAL_ROOT (repo path on server),
//! TRIAL_KEY (optional key file), TRIAL_KNOWN_HOSTS_STRATEGY (strict|add|accept),
//! TRIAL_PASSWORD, TRIAL_DIR (dir in "latest" to list), TRIAL_FILE (file to restore),
//! TRIAL_DEST (restore destination). Time and memory: run under `/usr/bin/time -l`.
use rustic_backend::BackendOptions;
use rustic_core::{Credentials, LocalDestination, LsOptions, Repository, RepositoryOptions, RestoreOptions};
use std::{env, error::Error, time::Instant};

fn var(name: &str) -> Result<String, Box<dyn Error>> {
    env::var(name).map_err(|_| format!("{name} not set").into())
}

fn main() -> Result<(), Box<dyn Error>> {
    let _ = simplelog::SimpleLogger::init(simplelog::LevelFilter::Info, simplelog::Config::default());
    let mut backend = BackendOptions::default().repository("opendal:sftp");
    backend.options.insert("endpoint".into(), var("TRIAL_ENDPOINT")?);
    backend.options.insert("root".into(), var("TRIAL_ROOT")?);
    if let Ok(key) = env::var("TRIAL_KEY") {
        backend.options.insert("key".into(), key);
    }
    if let Ok(s) = env::var("TRIAL_KNOWN_HOSTS_STRATEGY") {
        backend.options.insert("known_hosts_strategy".into(), s);
    }
    let backends = backend.to_backends()?;

    let t = Instant::now();
    let repo = Repository::new(&RepositoryOptions::default(), &backends)?
        .open(&Credentials::password(var("TRIAL_PASSWORD")?))?
        .to_indexed()?;
    println!("open+index: {:?}", t.elapsed());

    for s in repo.get_all_snapshots()? {
        println!("snapshot {} {} {:?}", s.id, s.time, s.paths);
    }

    let dir = repo.node_from_snapshot_path(&format!("latest:{}", var("TRIAL_DIR")?), |_| true)?;
    let t = Instant::now();
    for item in repo.ls(&dir, &LsOptions::default())? {
        println!("{:?}", item?.0);
    }
    println!("ls: {:?}", t.elapsed());

    let node = repo.node_from_snapshot_path(&format!("latest:{}", var("TRIAL_FILE")?), |_| true)?;
    let ls = repo.ls(&node, &LsOptions::default())?;
    let dest = LocalDestination::new(&var("TRIAL_DEST")?, true, !node.is_dir())?;
    let opts = RestoreOptions::default();
    let info = repo.prepare_restore(&opts, ls.clone(), &dest, false)?;
    repo.restore(info, &opts, ls, &dest)?;
    println!("restored");
    Ok(())
}
