use std::{
    fs,
    io::{Seek, SeekFrom, Write},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

use crate::{AgentError, replay_test_support::Fixture, replay_tests::Value};

#[test]
fn unknown_temporary_and_symlink_entries_fail_closed() {
    for name in ["unknown", ".state-head.tmp"] {
        let fixture = committed();
        fs::write(fixture.state.join(name), b"x").expect("unknown");
        assert_rollback(&fixture);
    }
    let fixture = committed();
    std::os::unix::fs::symlink("head.json", fixture.state.join("state-evil.json")).expect("link");
    assert_rollback(&fixture);
}

#[test]
fn state_only_anchor_only_and_content_tamper_fail_closed() {
    for state_side in [true, false] {
        let fixture = committed();
        let root = if state_side {
            &fixture.state
        } else {
            &fixture.anchor
        };
        let prefix = if state_side { "state-" } else { "anchor-" };
        fs::remove_file(find(root, prefix)).expect("remove one side");
        assert_rollback(&fixture);
    }
    let fixture = committed();
    let path = find(&fixture.state, "state-");
    let mut file = fs::OpenOptions::new()
        .write(true)
        .open(path)
        .expect("state");
    file.seek(SeekFrom::Start(1)).expect("seek");
    file.write_all(b"X").expect("tamper");
    file.sync_all().expect("sync");
    assert_rollback(&fixture);
}

#[test]
fn coordinated_tail_deletion_is_detected_by_independent_heads() {
    let fixture = Fixture::new();
    let ledger = fixture.ledger(1);
    for sequence in 1..=2 {
        ledger
            .update::<Value>(|_| Ok(Some(Value { sequence })))
            .expect("commit");
    }
    fs::remove_file(latest(&fixture.state, "state-")).expect("state tail");
    fs::remove_file(latest(&fixture.anchor, "anchor-")).expect("anchor tail");
    assert_rollback(&fixture);
}

#[test]
fn hardlinks_and_permission_substitution_fail_closed() {
    let fixture = committed();
    let state = find(&fixture.state, "state-");
    fs::hard_link(&state, fixture.state.join("copy")).expect("hardlink");
    assert_rollback(&fixture);
    drop(fixture);
    let fixture = committed();
    fs::set_permissions(
        find(&fixture.anchor, "anchor-"),
        fs::Permissions::from_mode(0o640),
    )
    .expect("mode");
    assert_rollback(&fixture);
}

fn committed() -> Fixture {
    let fixture = Fixture::new();
    fixture
        .ledger(1)
        .update::<Value>(|_| Ok(Some(Value { sequence: 1 })))
        .expect("commit");
    fixture
}
fn assert_rollback(fixture: &Fixture) {
    assert!(matches!(
        fixture.try_ledger("endpoint-a", 1),
        Err(AgentError::AuthorityRollback)
    ));
}
fn find(root: &Path, prefix: &str) -> PathBuf {
    fs::read_dir(root)
        .expect("entries")
        .map(|entry| entry.expect("entry").path())
        .find(|path| {
            path.file_name()
                .expect("name")
                .to_string_lossy()
                .starts_with(prefix)
        })
        .expect("managed file")
}
fn latest(root: &Path, prefix: &str) -> PathBuf {
    let mut paths: Vec<_> = fs::read_dir(root)
        .expect("entries")
        .map(|entry| entry.expect("entry").path())
        .filter(|path| {
            path.file_name()
                .expect("name")
                .to_string_lossy()
                .starts_with(prefix)
        })
        .collect();
    paths.sort();
    paths.pop().expect("latest")
}
