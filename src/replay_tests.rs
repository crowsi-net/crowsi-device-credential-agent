use serde::{Deserialize, Serialize};
use std::{fs, os::unix::fs::MetadataExt};

use crate::{
    AgentError,
    replay_test_support::{Fixture, matching},
};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Value {
    pub sequence: u64,
}

#[test]
fn durable_ledger_survives_restart_and_bounds_consecutive_history() {
    let fixture = Fixture::new();
    for sequence in 1..=8 {
        fixture
            .ledger(1)
            .update::<Value>(|current| {
                assert_eq!(
                    current.map(|value| value.sequence),
                    (sequence > 1).then_some(sequence - 1)
                );
                Ok(Some(Value { sequence }))
            })
            .expect("commit");
    }
    assert_eq!(
        fixture.ledger(1).load::<Value>().expect("restart"),
        Some(Value { sequence: 8 })
    );
    assert_eq!(matching(&fixture.state, "state-"), 3);
    assert_eq!(matching(&fixture.anchor, "anchor-"), 3);
}

#[test]
fn runtime_open_never_silently_initializes_empty_directories() {
    let fixture = Fixture::new_uninitialized();
    assert!(matches!(
        fixture.try_ledger("endpoint-a", 1),
        Err(AgentError::AuthorityRollback)
    ));
    fixture
        .initialize("test-ledger", 1)
        .expect("installer initialize");
    fixture
        .initialize("test-ledger", 1)
        .expect("exact idempotent retry");
    fixture.ledger(1).load::<Value>().expect("runtime open");
}

#[test]
fn deployment_and_configuration_generation_are_durable_ratchets() {
    let fixture = Fixture::new();
    fixture
        .ledger(7)
        .update::<Value>(|_| Ok(Some(Value { sequence: 1 })))
        .expect("initial");
    assert!(matches!(
        fixture.try_ledger("other-endpoint", 7),
        Err(AgentError::AuthorityRollback)
    ));
    assert!(matches!(
        fixture.try_ledger("endpoint-a", 6),
        Err(AgentError::AuthorityRollback)
    ));
    let upgraded = fixture.ledger(8);
    upgraded
        .update::<Value>(|value| Ok(value.cloned()))
        .expect("generation upgrade");
    assert_eq!(
        upgraded
            .load::<Value>()
            .expect("load")
            .expect("value")
            .sequence,
        1
    );
    assert!(matches!(
        fixture.try_ledger("endpoint-a", 7),
        Err(AgentError::AuthorityRollback)
    ));
}

#[test]
fn directories_and_every_managed_file_are_owner_only() {
    let fixture = Fixture::new();
    fixture
        .ledger(1)
        .update::<Value>(|_| Ok(Some(Value { sequence: 1 })))
        .expect("commit");
    for root in [&fixture.state, &fixture.anchor] {
        assert_eq!(fs::metadata(root).expect("directory").mode() & 0o777, 0o700);
        for entry in fs::read_dir(root).expect("entries") {
            let metadata = entry.expect("entry").metadata().expect("metadata");
            assert_eq!(metadata.mode() & 0o777, 0o600);
            assert_eq!(metadata.nlink(), 1);
            assert!(metadata.is_file());
        }
    }
}
