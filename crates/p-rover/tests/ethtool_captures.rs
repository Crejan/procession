//! The ethtool parsers against real captures, when there are any
//! (`tests/captures/<ethtool version>/`, see the README there).

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use p_rover::ethtool::Ethtool;
use p_rover::ethtool_cli::EthtoolCli;
use p_rover::runner::{Output, RunError, Runner};

struct Captured(BTreeMap<String, Output>);

impl Runner for Captured {
    fn run(&self, _program: &str, args: &[&str], _t: std::time::Duration) -> Result<Output, RunError> {
        // args end with the interface; the file name is the options with spaces as `_`.
        let opts = args[..args.len() - 1].join("_");
        self.0.get(&opts).cloned().ok_or_else(|| RunError::Failed("ethtool".into(), format!("no capture for {opts}")))
    }
}

fn load(dir: &Path) -> BTreeMap<String, Output> {
    let mut m = BTreeMap::new();
    for e in fs::read_dir(dir).unwrap().filter_map(Result::ok) {
        let name = e.file_name().to_string_lossy().into_owned();
        let Some(opts) = name.strip_suffix(".txt") else { continue };
        let read = |ext: &str| fs::read_to_string(dir.join(format!("{opts}.{ext}"))).unwrap_or_default();
        let code = read("code").trim().parse().unwrap_or(0);
        m.insert(
            opts.to_string(),
            Output { code: Some(code), stdout: fs::read_to_string(e.path()).unwrap(), stderr: read("err") },
        );
    }
    m
}

#[test]
fn real_captures_parse_into_something() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/captures");
    let dirs: Vec<_> = fs::read_dir(&root).unwrap().filter_map(Result::ok).filter(|e| e.path().is_dir()).collect();
    if dirs.is_empty() {
        eprintln!("SKIPPED: no ethtool captures in tests/captures/ (not run; see its README)");
        return;
    }
    for d in dirs {
        let caps = load(&d.path());
        let ok = |k: &str| caps.get(k).is_some_and(|o| o.code == Some(0));
        let (data, _) = EthtoolCli::new(Box::new(Captured(caps.clone()))).query("eth0");
        let v = d.file_name().to_string_lossy().into_owned();
        if ok("-i") {
            assert!(data.driver.as_ref().is_some_and(|d| d.driver.is_some()), "{v}: -i");
        }
        if ok("-S") || ok("--json_-S") {
            assert!(!data.stats.is_empty(), "{v}: -S");
        }
        if ok("-g") || ok("--json_-g") {
            assert!(data.ring.as_ref().is_some_and(|r| r.rx.is_some() || r.tx.is_some()), "{v}: -g");
        }
        if ok("-c") || ok("--json_-c") {
            assert!(data.coalesce.as_ref().is_some_and(|c| c.rx_usecs.is_some()), "{v}: -c");
        }
        if ok("-l") || ok("--json_-l") {
            assert!(data.channels.as_ref().is_some_and(|c| c.combined.is_some() || c.rx.is_some()), "{v}: -l");
        }
        if ok("--show-eee") || ok("--json_--show-eee") {
            assert!(data.eee.is_some(), "{v}: --show-eee");
        }
        if ok("-k") || ok("--json_-k") {
            assert!(!data.features.is_empty(), "{v}: -k");
        }
    }
}
