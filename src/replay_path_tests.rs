use std::{
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt},
};

use crate::{AgentError, replay::DurableLedger, replay_test_support::Fixture, replay_tests::Value};

#[test]
fn caller_supplied_uid_and_owner_only_directory_modes_are_mandatory() {
    let fixture = Fixture::new();
    let uid = fs::metadata(&fixture.state).expect("metadata").uid();
    assert!(matches!(
        DurableLedger::open(
            &fixture.state,
            &fixture.anchor,
            uid.wrapping_add(1),
            "endpoint-a",
            1,
            "test-ledger"
        ),
        Err(AgentError::PathInvalid)
    ));
    fs::set_permissions(&fixture.anchor, fs::Permissions::from_mode(0o750)).expect("mode");
    assert!(matches!(
        fixture.try_ledger("endpoint-a", 1),
        Err(AgentError::PathInvalid)
    ));
}

#[test]
fn symlinked_or_replaced_directory_paths_never_retarget_pinned_fds() {
    let fixture = Fixture::new();
    let alias = fixture.state.parent().expect("root").join("state-alias");
    std::os::unix::fs::symlink(&fixture.state, &alias).expect("alias");
    let uid = fs::metadata(&fixture.state).expect("metadata").uid();
    assert!(matches!(
        DurableLedger::open(&alias, &fixture.anchor, uid, "endpoint-a", 1, "test-ledger"),
        Err(AgentError::PathInvalid)
    ));
    fs::remove_file(alias).expect("remove alias");
    let ledger = fixture.ledger(1);
    let moved = fixture.state.parent().expect("root").join("state-moved");
    fs::rename(&fixture.state, &moved).expect("move pinned directory");
    fs::create_dir(&fixture.state).expect("replacement");
    fs::set_permissions(&fixture.state, fs::Permissions::from_mode(0o700)).expect("mode");
    assert_eq!(ledger.load::<Value>(), Err(AgentError::AuthorityRollback));
}

#[test]
fn hardlinked_guard_or_known_file_is_rejected_before_use() {
    let fixture = Fixture::new();
    fs::hard_link(
        fixture.state.join("ledger.lock"),
        fixture.state.join("lock-copy"),
    )
    .expect("link");
    assert!(matches!(
        fixture.try_ledger("endpoint-a", 1),
        Err(AgentError::AuthorityRollback)
    ));
}

#[test]
fn writable_or_changed_ancestor_is_rejected_before_every_transaction() {
    let fixture = Fixture::new();
    let parent = fixture.state.parent().expect("parent");
    fs::set_permissions(parent, fs::Permissions::from_mode(0o770)).expect("writable parent");
    assert!(matches!(
        fixture.try_ledger("endpoint-a", 1),
        Err(AgentError::PathInvalid)
    ));
    fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).expect("restore");
    let ledger = fixture.ledger(1);
    fs::set_permissions(parent, fs::Permissions::from_mode(0o770)).expect("change parent");
    assert_eq!(ledger.load::<Value>(), Err(AgentError::AuthorityRollback));
}
