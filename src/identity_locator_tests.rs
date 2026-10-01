use serde_json::json;
use std::{
    os::unix::fs::MetadataExt,
    sync::{Arc, Barrier},
};

use crate::{
    AgentError, identity_locator::IdentitySessionLocatorV1, replay::DurableSecurityState,
    replay_test_support::Fixture,
};

#[test]
fn locator_is_exclusive_and_uses_exact_on_disk_cas() {
    let fixture = Fixture::new_uninitialized();
    let state = security(&fixture);
    let store = state.identity_locator();
    let first = value("a", 1, 1);
    store.create_value(&first).expect("exclusive create");
    assert_eq!(
        store.create_value(&first),
        Err(AgentError::AuthorityRollback)
    );
    let second = value("b", 2, 2);
    store
        .compare_and_swap_test(&first, &second)
        .expect("advance");
    assert_eq!(
        store.compare_and_swap_test(&first, &value("c", 3, 3)),
        Err(AgentError::AuthorityRollback)
    );
    assert_eq!(store.load_value().expect("restart"), Some(second));
}

#[test]
fn reordered_old_identity_response_cannot_restore_a_previous_session() {
    let fixture = Fixture::new_uninitialized();
    let state = security(&fixture);
    let store = state.identity_locator();
    let first = value("a", 10, 4);
    store.create_value(&first).expect("create");
    let current = value("b", 20, 5);
    store
        .compare_and_swap_test(&first, &current)
        .expect("new session");
    assert_eq!(
        crate::identity_locator_validation::current(&current, &value("a", 10, 4)),
        Err(AgentError::AuthorityRollback)
    );
    assert_eq!(
        crate::identity_locator_validation::current(&current, &value("c", 20, 5)),
        Err(AgentError::AuthorityRollback)
    );
}

#[test]
fn passive_current_observation_cannot_rotate_or_replace_an_equal_ratchet() {
    let current = value("a", 10, 4);
    crate::identity_locator_validation::current(&current, &current).expect("exact idempotency");
    let mut replay = current.clone();
    replay.updated_at_epoch_s = 11;
    crate::identity_locator_validation::current(&current, &replay)
        .expect("exact authority response replay at a later local time");
    let mut equal = current.clone();
    equal.response_command_digest = "b".repeat(64);
    assert_eq!(
        crate::identity_locator_validation::current(&current, &equal),
        Err(AgentError::AuthorityRollback)
    );
    let mut later = equal;
    later.authority_issued_at_epoch_s = 11;
    later.updated_at_epoch_s = 11;
    crate::identity_locator_validation::current(&current, &later).expect("later current response");
    later.session_ref = format!("sref_{}", "c".repeat(64));
    assert_eq!(
        crate::identity_locator_validation::current(&current, &later),
        Err(AgentError::AuthorityRollback)
    );
}

#[test]
fn concurrent_stale_writers_cannot_both_advance_the_locator() {
    let fixture = Fixture::new_uninitialized();
    let state = Arc::new(security(&fixture));
    let first = value("a", 10, 1);
    state
        .identity_locator()
        .create_value(&first)
        .expect("create");
    let barrier = Arc::new(Barrier::new(3));
    let mut handles = Vec::new();
    for session in ["b", "c"] {
        let state = Arc::clone(&state);
        let barrier = Arc::clone(&barrier);
        let expected = first.clone();
        let next = value(session, 20, 2);
        handles.push(std::thread::spawn(move || {
            barrier.wait();
            state
                .identity_locator()
                .compare_and_swap_test(&expected, &next)
        }));
    }
    barrier.wait();
    let successes = handles
        .into_iter()
        .map(|handle| handle.join().expect("writer"))
        .filter(Result::is_ok)
        .count();
    assert_eq!(successes, 1);
}

fn security(fixture: &Fixture) -> DurableSecurityState {
    let uid = std::fs::metadata(&fixture.state).expect("uid").uid();
    DurableSecurityState::initialize_once(&fixture.state, &fixture.anchor, uid, "endpoint-a", 1)
        .expect("initialize");
    DurableSecurityState::open(&fixture.state, &fixture.anchor, uid, "endpoint-a", 1)
        .expect("state")
}

fn value(session: &str, issued: u64, generation: u64) -> IdentitySessionLocatorV1 {
    serde_json::from_value(json!({"schema":"crowsi://device-credential-agent/identity-session-locator/v2","issuer":"issuer","service_id":"service","pairwise_subject":"subject","device_id":"device","session_ref":format!("sref_{}", session.repeat(64)),"sender_key_fingerprint":"a".repeat(64),"subject_revocation_epoch":1,"service_revocation_epoch":1,"device_revocation_epoch":1,"session_revocation_epoch":generation,"device_posture_state":"compliant","device_posture_revision":generation,"device_proof_key_ref":"proof","response_config_generation":generation,"response_command_digest":session.repeat(64),"authority_issued_at_epoch_s":issued,"updated_at_epoch_s":issued})).expect("locator")
}
