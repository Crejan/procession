//! A throwaway repository for tests. This is the only code in the crate that
//! writes to a repository, and it is only built for tests (`cfg(test)` or the
//! `testing` feature); it must never be pointed at a real one.

use std::path::Path;

use rustic_backend::BackendOptions;
use rustic_core::{
    BackupOptions, ConfigOptions, Credentials, KeyOptions, PathList, Repository, RepositoryOptions, SnapshotOptions,
};

/// Initialise a new repository at `repo` (a directory that does not exist yet
/// or is empty) with `password`, and store one snapshot of `source` in it.
///
/// # Panics
/// On any error: it is a test helper.
pub fn make_repository(repo: &Path, password: &str, source: &Path) {
    let backends =
        BackendOptions::default().repository(repo.to_str().expect("utf-8 path")).to_backends().expect("backend");
    let repository = Repository::new(&RepositoryOptions::default(), &backends)
        .expect("repository")
        .init(&Credentials::password(password), &KeyOptions::default(), &ConfigOptions::default())
        .expect("init")
        .to_indexed_ids()
        .expect("index");
    let paths =
        PathList::from_string(source.to_str().expect("utf-8 path")).expect("paths").sanitize().expect("sanitize");
    let snapshot = SnapshotOptions::default().to_snapshot().expect("snapshot options");
    repository.backup(&BackupOptions::default(), &paths, snapshot).expect("backup");
}
