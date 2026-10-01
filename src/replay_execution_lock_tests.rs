use std::{fs, os::unix::fs::MetadataExt, sync::mpsc, time::Duration};

use crate::{AgentError, replay::DurableSecurityState, replay_test_support::Fixture};

#[test]
fn execution_lock_serializes_whole_commands_and_rejects_hardlinks() {
    let fixture = Fixture::new_uninitialized();
    let uid = fs::metadata(&fixture.state).expect("uid").uid();
    DurableSecurityState::initialize_once(&fixture.state, &fixture.anchor, uid, "endpoint-a", 1)
        .expect("initialize");
    let first = open(&fixture, uid);
    let second = open(&fixture, uid);
    let (entered_tx, entered_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let (second_tx, second_rx) = mpsc::channel();
    std::thread::scope(|scope| {
        scope.spawn(move || {
            first
                .exclusive(|| {
                    entered_tx.send(()).expect("entered");
                    release_rx.recv().expect("release");
                    Ok(())
                })
                .expect("first command");
        });
        entered_rx.recv().expect("first acquired");
        scope.spawn(move || {
            second
                .exclusive(|| {
                    second_tx.send(()).expect("second entered");
                    Ok(())
                })
                .expect("second command");
        });
        assert!(second_rx.recv_timeout(Duration::from_millis(50)).is_err());
        release_tx.send(()).expect("release first");
        second_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("second acquired after release");
    });

    let state = open(&fixture, uid);
    fs::hard_link(
        fixture.state.join("execution.lock"),
        fixture.state.join("execution-link"),
    )
    .expect("hardlink");
    assert_eq!(
        state.exclusive(|| Ok(())),
        Err(AgentError::AuthorityRollback)
    );
}

fn open(fixture: &Fixture, uid: u32) -> DurableSecurityState {
    DurableSecurityState::open(&fixture.state, &fixture.anchor, uid, "endpoint-a", 1)
        .expect("open state")
}
