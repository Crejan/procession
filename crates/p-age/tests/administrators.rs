//! `administrators_group`: members of one group connect to `admin.sock` as themselves, so the register names them.
//! Admission is from the kernel only. What needs a second account, or the Linux kernel's list of a peer's groups, is
//! marked `#[cfg(target_os = "linux")]` or is tested through the pure rule (`admits`).

mod common;

use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::time::Duration;

use common::*;
use p_age::admin::{AdminGroup, GroupError, admits, bind_for, resolve_group_with};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const OWN: u32 = 501;

fn group(gid: u32) -> AdminGroup {
    AdminGroup { name: "page-admins".to_owned(), gid }
}

#[test]
fn the_rule_admits_root_and_members_by_primary_or_supplementary_group_and_never_the_brokers_own_user() {
    let none = || Err::<Vec<u32>, ()>(());
    let g = group(900);
    // without a group: root and the broker's user, as before
    assert!(admits(None, (0, 0), OWN, none) && admits(None, (OWN, 20), OWN, none));
    assert!(!admits(None, (502, 900), OWN, || Ok::<_, ()>(vec![900])));
    // with one: root always; a member by primary gid (no list is read); a member by a supplementary group
    assert!(admits(Some(&g), (0, 0), OWN, none));
    assert!(admits(Some(&g), (502, 900), OWN, || -> Result<Vec<u32>, ()> { panic!("the primary group decided") }));
    assert!(admits(Some(&g), (502, 20), OWN, || Ok::<_, ()>(vec![5, 900])));
    // not a member, and a peer whose groups cannot be read, are dropped, never admitted
    assert!(!admits(Some(&g), (502, 20), OWN, || Ok::<_, ()>(vec![5, 6])));
    assert!(!admits(Some(&g), (502, 20), OWN, none));
    // the broker's own user is refused although it is in the group, by either way in
    assert!(!admits(Some(&g), (OWN, 900), OWN, || Ok::<_, ()>(vec![900])));
}

#[test]
fn a_group_that_cannot_be_used_refuses_the_start_naming_the_member() {
    let found = |gid: u32| move |_: &str| Ok(Some(gid));
    assert_eq!(resolve_group_with("ops", true, found(900), 20), Ok(group_named("ops", 900)));
    assert_eq!(resolve_group_with("nope", true, |_| Ok(None), 20), Err(GroupError::Unknown));
    assert_eq!(resolve_group_with("wheel", true, found(0), 20), Err(GroupError::Root));
    assert_eq!(resolve_group_with("staff", true, found(20), 20), Err(GroupError::OwnPrimary));
    assert_eq!(resolve_group_with("ops", false, found(900), 20), Err(GroupError::Unsupported));
    assert!(matches!(resolve_group_with("ops", true, |_| Err("db".into()), 20), Err(GroupError::Lookup(_))));
    assert_eq!(resolve_group_with("a\u{85}b", true, found(900), 20), Err(GroupError::BadName));
    for e in [GroupError::Unsupported, GroupError::Unknown, GroupError::Root, GroupError::OwnPrimary] {
        assert!(e.to_string().contains("administrators_group"), "{e}");
    }
    assert!(GroupError::Unsupported.to_string().contains("not supported here"));
}

fn group_named(name: &str, gid: u32) -> AdminGroup {
    AdminGroup { name: name.to_owned(), gid }
}

#[test]
fn the_configuration_with_a_group_that_is_not_there_does_not_build() {
    let w = World::new();
    let text = std::fs::read_to_string(config_file(&w)).unwrap();
    let with = text.replacen('{', r#"{"administrators_group":"no-such-group-for-page-tests","#, 1);
    let path = std::env::temp_dir().join(format!("page-admins-{}.json", std::process::id()));
    std::fs::write(&path, with).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    let config = p_age::config::Config::read(&path).unwrap();
    let err = config.build().err().expect("a group that is not there refuses the start").to_string();
    // Linux: no such group; elsewhere: not supported here. Either way it names the member.
    assert!(err.contains("administrators_group"), "{err}");
}

#[tokio::test]
async fn the_socket_and_its_directory_are_given_to_the_group_and_checked_and_a_failure_refuses_the_start() {
    let dir = tempfile::tempdir_in(socket_base()).unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let own_gid = std::fs::metadata(dir.path()).unwrap().gid();
    let _listener = bind_for(dir.path(), Some(&group(own_gid))).unwrap();
    let sock = std::fs::symlink_metadata(dir.path().join("admin.sock")).unwrap();
    assert!(sock.file_type().is_socket());
    assert_eq!((sock.gid(), sock.mode() & 0o7777), (own_gid, 0o660));
    let d = std::fs::metadata(dir.path()).unwrap();
    assert_eq!((d.gid(), d.mode() & 0o7777), (own_gid, 0o710), "the group may traverse and nobody else");
    // a group the broker's account is not in cannot be given the socket: the start is refused
    if p_ermit::peer::own_uid() != 0 {
        let other = tempfile::tempdir_in(socket_base()).unwrap();
        std::fs::set_permissions(other.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let stranger = if own_gid == 4242 { 4243 } else { 4242 };
        let e = bind_for(other.path(), Some(&group(stranger))).expect_err("refused");
        assert!(e.to_string().contains("cannot be given to the administrators' group"), "{e}");
    }
}

#[tokio::test]
async fn with_a_group_configured_the_brokers_own_user_is_dropped_unread_and_nothing_changes() {
    let w = World::new();
    // a core that has a group configured: the test's own user is the broker's user, so it is refused
    w.broker.set_administrators(Some(group(900)));
    let broker = w.broker.clone();
    let dir = tempfile::tempdir_in(socket_base()).unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let listener = p_age::admin::bind(dir.path()).unwrap();
    tokio::spawn(p_age::admin::serve(listener, broker.clone()));
    let mut stream = tokio::net::UnixStream::connect(p_age::admin::socket_path(dir.path())).await.unwrap();
    let _ = stream.write_all(&p_age::admin::Command::Block(p_age::admin::Target::Person("jan".into())).encode()).await;
    let mut answer = Vec::new();
    let read = tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut answer)).await;
    assert!(read.is_ok(), "the connection was closed");
    assert!(answer.is_empty(), "dropped without an answer");
    let p_age::admin::Reply::Status(s) = p_age::admin::execute(&broker, p_age::admin::Command::Status).await else {
        panic!("status")
    };
    assert!(s.blocked_persons.is_empty(), "nothing was read, so nothing was done");
}

#[test]
fn status_says_who_may_administer_and_page_says_when_it_runs_as_root() {
    let status = |administrators| p_age::core::Status { administrators, ..base_status() };
    let text = |s: &p_age::core::Status| {
        p_age::admin::render(&p_age::admin::Command::Status, &p_age::admin::Reply::Status(Box::new(s.clone()))).0
    };
    assert!(text(&status(None)).contains("administrators: root and the broker's account (uid 501)"));
    assert!(!text(&status(None)).contains("root only"));
    assert!(text(&status(Some(group(900)))).contains("administrators: group page-admins (gid 900)"));
    assert!(p_age::admin::recorded_as_root(true, 0));
    assert!(!p_age::admin::recorded_as_root(true, 501) && !p_age::admin::recorded_as_root(false, 0));
    assert_eq!(p_age::admin::ROOT_NOTICE, "page: recorded as root; run without sudo to be recorded by name");
}

fn base_status() -> p_age::core::Status {
    p_age::core::Status {
        administrators: None,
        broker_uid: 501,
        keygen_unusable: None,
        degraded: None,
        pledges: 0,
        held: 0,
        delegations: 0,
        withdrawn: 0,
        blocked_persons: vec![],
        blocked_keys: vec![],
        broker_certificate: p_age::core::BrokerCertificateStatus {
            path: "/x".into(),
            valid: true,
            days_left: Some(3),
            failure: None,
        },
        certificates: None,
    }
}

/// Linux only (not compiled elsewhere): the kernel's list of a peer's supplementary groups, read from a real socket,
/// is the process's own (`/proc/self/status`), and a connection whose groups are read admits by them.
#[cfg(target_os = "linux")]
#[test]
fn linux_the_peers_supplementary_groups_are_read_from_the_kernel() {
    let (a, _b) = std::os::unix::net::UnixStream::pair().unwrap();
    let from_kernel = p_ermit::peer::peer_groups(&a).unwrap();
    let status = std::fs::read_to_string("/proc/self/status").unwrap();
    let mut expected: Vec<u32> = status
        .lines()
        .find_map(|l| l.strip_prefix("Groups:"))
        .unwrap_or("")
        .split_whitespace()
        .filter_map(|g| g.parse().ok())
        .collect();
    let mut got = from_kernel;
    got.sort_unstable();
    expected.sort_unstable();
    assert_eq!(got, expected);
}

/// Linux only: a member by supplementary group (one this process is in) is admitted by the real credentials, as
/// long as the peer is not the broker's own user: here the pair's peer is this very process, so it is refused by
/// that rule and **not** admitted by its groups.
#[cfg(target_os = "linux")]
#[test]
fn linux_a_connection_of_the_brokers_own_user_is_refused_even_when_its_group_is_the_configured_one() {
    let (a, _b) = std::os::unix::net::UnixStream::pair().unwrap();
    let groups = p_ermit::peer::peer_groups(&a).unwrap();
    let Some(gid) = groups.first().copied().filter(|g| *g != 0) else { return };
    let mut throttle = p_act::peer::Throttle::new("page", Duration::from_secs(1));
    let mut lines = Vec::new();
    let admitted =
        p_age::admin::admitted_uid_for(&a, Some(&group(gid)), &mut throttle, &mut |l| lines.push(l.to_owned()));
    assert_eq!(admitted, None);
}

/// What one account can show of the order: at every step the state directory is the broker's own and exactly 0700
/// until the socket has been given to the group, so that whatever mode the socket has meanwhile (the process umask's
/// at `bind`: run this under `umask 000` too) no other user can reach it. It does **not** show another uid failing to
/// connect (that is the owner's two-account check on Debian), and it cannot set a umask of its own (no libc here): the
/// umask is the shell's.
#[tokio::test]
async fn the_directory_is_the_guard_at_every_step_of_bind() {
    use p_age::admin::{BindStep, bind_for_watched};
    let base = tempfile::tempdir_in(socket_base()).unwrap();
    let dir = base.path().join("state");
    std::fs::create_dir(&dir).unwrap();
    // a 0710 left by a former run is made 0700 before anything is bound
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o710)).unwrap();
    let own_gid = std::fs::metadata(&dir).unwrap().gid();
    let sock = dir.join("admin.sock");
    let mut seen: Vec<(BindStep, u32, Option<u32>)> = Vec::new();
    let mode = |p: &std::path::Path| std::fs::symlink_metadata(p).ok().map(|m| m.mode() & 0o7777);
    let _listener = bind_for_watched(&dir, Some(&group(own_gid)), &mut |step| {
        seen.push((step, mode(&dir).unwrap(), mode(&sock)));
    })
    .unwrap();
    let steps: Vec<_> = seen.iter().map(|s| s.0).collect();
    assert_eq!(
        steps,
        [
            BindStep::DirectoryChecked,
            BindStep::Bound,
            BindStep::SocketPrivate,
            BindStep::SocketToGroup,
            BindStep::DirectoryToGroup,
            BindStep::Checked
        ]
    );
    for (step, dir_mode, socket_mode) in &seen {
        match step {
            BindStep::DirectoryToGroup | BindStep::Checked => assert_eq!(*dir_mode, 0o710, "{step:?}"),
            _ => assert_eq!(*dir_mode, 0o700, "{step:?}: nobody else can enter yet"),
        }
        match step {
            BindStep::DirectoryChecked => assert_eq!(*socket_mode, None),
            BindStep::Bound => {}
            BindStep::SocketPrivate => assert_eq!(*socket_mode, Some(0o600)),
            _ => assert_eq!(*socket_mode, Some(0o660), "{step:?}"),
        }
    }
    // a directory that is not the broker's own plain 0700 (or a link to one) refuses the start
    let wide = base.path().join("wide");
    std::fs::create_dir(&wide).unwrap();
    std::fs::set_permissions(&wide, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(bind_for(&wide, None).is_err());
    let link = base.path().join("link");
    std::os::unix::fs::symlink(&dir, &link).unwrap();
    assert!(bind_for(&link, None).is_err());
}
