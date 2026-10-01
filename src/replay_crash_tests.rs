use std::os::unix::fs::MetadataExt;

use crate::{replay_commit_fault::fail_after, replay_test_support::Fixture, replay_tests::Value};

#[test]
fn restart_exactly_rolls_back_or_forward_finishes_every_commit_cut() {
    for point in 1..=10 {
        let fixture = Fixture::new();
        let ledger = fixture.ledger(1);
        fail_after(point);
        assert!(
            ledger
                .update::<Value>(|_| Ok(Some(Value { sequence: 1 })))
                .is_err(),
            "cut {point}"
        );
        drop(ledger);
        let recovered = fixture.ledger(1).load::<Value>().expect("recovery");
        if point <= 5 {
            assert_eq!(recovered, None, "rollback cut {point}");
        } else {
            assert_eq!(
                recovered,
                Some(Value { sequence: 1 }),
                "forward cut {point}"
            );
        }
    }
}

#[test]
fn installer_genesis_is_exactly_recoverable_at_every_commit_cut() {
    for point in 1..=10 {
        let fixture = Fixture::new_uninitialized();
        let uid = std::fs::metadata(&fixture.state).expect("metadata").uid();
        fail_after(point);
        assert!(
            crate::replay::DurableSecurityState::initialize_once(
                &fixture.state,
                &fixture.anchor,
                uid,
                "endpoint-a",
                1,
            )
            .is_err(),
            "cut {point}"
        );
        crate::replay::DurableSecurityState::initialize_once(
            &fixture.state,
            &fixture.anchor,
            uid,
            "endpoint-a",
            1,
        )
        .expect("resume initializer");
        crate::replay::DurableSecurityState::open(
            &fixture.state,
            &fixture.anchor,
            uid,
            "endpoint-a",
            1,
        )
        .expect("runtime genesis");
    }
}

#[test]
fn restart_finishes_post_commit_pruning_without_losing_the_head() {
    let fixture = Fixture::new();
    let ledger = fixture.ledger(1);
    for sequence in 1..=3 {
        ledger
            .update::<Value>(|_| Ok(Some(Value { sequence })))
            .expect("seed");
    }
    fail_after(11);
    assert!(
        ledger
            .update::<Value>(|_| Ok(Some(Value { sequence: 4 })))
            .is_err()
    );
    drop(ledger);
    assert_eq!(
        fixture.ledger(1).load::<Value>().expect("recover"),
        Some(Value { sequence: 4 })
    );
    assert_eq!(
        crate::replay_test_support::matching(&fixture.state, "state-"),
        3
    );
    assert_eq!(
        crate::replay_test_support::matching(&fixture.anchor, "anchor-"),
        3
    );
}
