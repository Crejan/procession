//! What the register keeps beside the fingerprints (v 1, the draft): a delegation's groups, label and when it was
//! registered; for each block and withdrawal when and by whom. The uid is the record; the account's name is added
//! afterwards and never stands between an administrator and a block.

mod common;

use std::time::{Duration, Instant};

use common::*;
use p_age::admin::{Command, Reply, Target, execute_as};
use p_age::register::Actor;

fn disk(w: &World) -> serde_json::Value {
    serde_json::from_slice(&std::fs::read(w.keys.path("register.json")).unwrap()).unwrap()
}

async fn until(what: &str, mut ok: impl FnMut() -> bool) {
    let start = Instant::now();
    while !ok() {
        assert!(start.elapsed() < Duration::from_secs(10), "{what}");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[tokio::test]
async fn a_registration_keeps_its_label_and_time_and_a_withdrawal_its_time_and_the_pledge_that_made_it() {
    let w = World::new();
    let mut pledge = open_pledge(&w).await;
    pledge.connect_as("jan", &w.jan_connection).await;
    let cert = w.keys.cert_line(&w.agent);
    pledge.send_json(serde_json::json!({"schema_version":1,"type":"delegation","cert":cert})).await;
    assert_eq!(pledge.recv().await["type"], "registered");
    let agent = p_act::sign::agent_certificate(&cert).unwrap();
    let d = disk(&w)["delegations"][0].clone();
    assert_eq!(d["registered"].as_i64(), Some(w.clock.unix()));
    assert_eq!(d["label"].as_str(), Some(agent.key_id.as_str()));
    assert_eq!(d["groups"], serde_json::json!(agent.groups));
    assert!(d.get("withdrawal").is_none());
    w.clock.advance(7);
    pledge
        .send_json(serde_json::json!({"schema_version":1,"type":"withdraw","delegation":agent.delegation.to_string()}))
        .await;
    assert_eq!(pledge.recv().await["type"], "withdrawn");
    let d = disk(&w)["delegations"][0].clone();
    assert_eq!(d["withdrawal"], serde_json::json!({"at": w.clock.unix(), "by": {"kind": "pledge", "person": "jan"}}));
}

#[tokio::test]
async fn a_block_records_the_uid_first_and_the_account_name_is_added_afterwards() {
    let w = World::new();
    let reply = execute_as(&w.broker, Command::Block(Target::Person("jan".into())), 4242).await;
    assert_eq!(reply, Reply::Done(Ok(())));
    // the uid is stored with the block; the name is not looked up for a uid the system does not have
    let block = disk(&w)["blocked"][0].clone();
    assert_eq!(block["name"], "jan");
    assert_eq!(
        (block["at"].as_i64(), &block["by"]["kind"], block["by"]["uid"].as_u64()),
        (Some(w.clock.unix()), &"administrator".into(), Some(4242))
    );
    // a name that comes later is added to the entry, and the register is written again
    w.broker.name_administrator_later_with(4242, |uid| (uid == 4242).then(|| "alice".to_owned()));
    until("the account name is added", || disk(&w)["blocked"][0]["by"]["account"] == "alice").await;
    // sudo: uid 0 and nothing more; the environment of the caller is never read
    no_environment_is_read();
    let reply = execute_as(&w.broker, Command::Block(Target::Person("eva".into())), 0).await;
    assert_eq!(reply, Reply::Done(Ok(())));
    let eva = disk(&w)["blocked"].as_array().unwrap().iter().find(|b| b["name"] == "eva").cloned().unwrap();
    assert_eq!(eva["by"]["uid"].as_u64(), Some(0));
}

/// `SUDO_USER` is not read: nothing in p-age mentions it.
fn no_environment_is_read() {
    for file in ["admin.rs", "core.rs", "net.rs", "register.rs", "main.rs"] {
        let text = std::fs::read_to_string(format!("{}/src/{file}", env!("CARGO_MANIFEST_DIR"))).unwrap();
        let code: String = text.lines().filter(|l| !l.trim_start().starts_with("//")).collect();
        assert!(!code.contains("SUDO_USER") && !code.contains("env::var"), "{file} reads the environment");
    }
}

#[tokio::test]
async fn a_lookup_that_never_returns_does_not_stand_between_an_administrator_and_a_block() {
    let w = World::new();
    // the lookup for this uid hangs for ever (a name service that does not answer)
    w.broker.name_administrator_later_with(77, |_| {
        loop {
            std::thread::park();
        }
    });
    let by = Actor::Administrator { uid: 77, account: None };
    let stored = tokio::time::timeout(Duration::from_secs(5), w.broker.block_person("jan".into(), by)).await;
    assert!(stored.is_ok(), "the verb was answered");
    // in force, and stored with the uid and without a name: an entry without a name is complete
    let Reply::Status(s) = execute_as(&w.broker, Command::Status, 77).await else { panic!("status") };
    assert_eq!(s.blocked_persons, ["jan"]);
    let block = disk(&w)["blocked"][0].clone();
    assert_eq!(block["by"], serde_json::json!({"kind": "administrator", "uid": 77}));
}

#[test]
fn what_is_read_back_is_validated_and_a_register_that_fails_is_refused_whole() {
    use p_age::register::{Register, Snapshot};
    let bad = "x\u{85}y\u{202e}z";
    let fp = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    let delegation = |extra: serde_json::Value| {
        let mut d = serde_json::json!({"fingerprint": fp, "person": "jan", "until": 9, "withdrawn": false});
        d.as_object_mut().unwrap().extend(extra.as_object().unwrap().clone());
        serde_json::json!({"v": 1, "delegations": [d], "blocked": []})
    };
    let admin = |account: &str| serde_json::json!({"kind": "administrator", "uid": 1, "account": account});
    for (value, member) in [
        (delegation(serde_json::json!({"groups": [bad]})), "delegations (groups)"),
        (delegation(serde_json::json!({"label": bad})), "delegations (label)"),
        (delegation(serde_json::json!({"label": "x".repeat(300)})), "delegations (label)"),
        (delegation(serde_json::json!({"withdrawal": {"at": 1, "by": admin(bad)}})), "delegations (withdrawal)"),
        (
            serde_json::json!({"v": 1, "delegations": [], "blocked": [{"name": "jan", "at": 1, "by": admin(bad)}]}),
            "blocked",
        ),
        (
            serde_json::json!({"v": 1, "delegations": [], "blocked": [{"name": "jan", "at": 1, "by": {"kind": "pledge", "person": bad}}]}),
            "blocked",
        ),
    ] {
        let snapshot: Snapshot = serde_json::from_value(value).unwrap();
        assert_eq!(Register::restore(snapshot).err(), Some(member));
    }
    // and an entry that is fine is read, with or without an account
    let ok: Snapshot = serde_json::from_value(serde_json::json!({"v": 1, "delegations": [], "blocked": [
        {"name": "jan", "at": 1, "by": admin("alice")}, {"name": "eva", "at": 2, "by": {"kind": "administrator", "uid": 0}}]}))
    .unwrap();
    assert!(Register::restore(ok).is_ok());
}
