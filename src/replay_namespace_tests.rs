use serde::{Deserialize, Serialize};
use std::os::unix::fs::MetadataExt;

use crate::{AgentError, replay::DurableLedger, replay_test_support::Fixture};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct Record {
    value: u64,
}

#[test]
fn multiple_security_namespaces_commit_in_one_generation() {
    let fixture = Fixture::new_for("endpoint-security-state");
    let ledger = open(&fixture);
    ledger
        .transaction_namespaces(|values| {
            values.put("management-projection", &Record { value: 1 })?;
            values.put("identity-session-locator", &Record { value: 2 })?;
            Ok(((), true))
        })
        .expect("atomic commit");
    assert_eq!(
        ledger
            .load_namespace::<Record>("management-projection")
            .expect("projection"),
        Some(Record { value: 1 })
    );
    assert_eq!(
        ledger
            .load_namespace::<Record>("identity-session-locator")
            .expect("locator"),
        Some(Record { value: 2 })
    );
    assert_eq!(
        crate::replay_test_support::matching(&fixture.state, "state-"),
        1
    );
}

#[test]
fn unknown_namespace_and_failed_multi_update_leave_no_partial_state() {
    let fixture = Fixture::new_for("endpoint-security-state");
    let ledger = open(&fixture);
    assert_eq!(
        ledger.transaction_namespaces::<()>(|values| {
            values.put("management-projection", &Record { value: 1 })?;
            Err(AgentError::AuthorityUnavailable)
        }),
        Err(AgentError::AuthorityUnavailable)
    );
    assert_eq!(
        ledger
            .load_namespace::<Record>("management-projection")
            .expect("load"),
        None
    );
    assert_eq!(
        ledger.transaction_namespaces::<()>(|values| {
            values.put("future-namespace", &Record { value: 1 })?;
            Ok(((), true))
        }),
        Err(AgentError::AuthorityRollback)
    );
}

#[test]
fn hostile_growth_is_rejected_without_evicting_current_identity() {
    let fixture = Fixture::new_for("endpoint-security-state");
    let ledger = open(&fixture);
    ledger
        .update_namespace("identity-session-locator", |_| {
            Ok(Some(Record { value: 7 }))
        })
        .expect("locator");
    let oversized = vec!["x".repeat(600); 256];
    assert_eq!(
        ledger.update_namespace("operation-journal", |_| Ok(Some(oversized))),
        Err(AgentError::AuthorityRollback)
    );
    let too_many = vec![Record { value: 1 }; 257];
    assert_eq!(
        ledger.update_namespace("transport-replay", |_| Ok(Some(too_many))),
        Err(AgentError::AuthorityRollback)
    );
    assert_eq!(
        ledger
            .load_namespace::<Record>("identity-session-locator")
            .expect("locator"),
        Some(Record { value: 7 })
    );
}

#[test]
fn duplicate_namespace_keys_are_not_canonical_ledger_wire() {
    let wire = br#"{"schema":"crowsi://device-agent/security-namespaces/v1","records":{"transport-replay":{},"transport-replay":{}}}"#;
    assert!(
        crate::replay_scan_names::decode::<crate::replay_namespace::SecurityNamespaces>(wire)
            .is_err()
    );
}

fn open(fixture: &Fixture) -> DurableLedger {
    DurableLedger::open(
        &fixture.state,
        &fixture.anchor,
        std::fs::metadata(&fixture.state).expect("metadata").uid(),
        "endpoint-a",
        1,
        "endpoint-security-state",
    )
    .expect("ledger")
}
