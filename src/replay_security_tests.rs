use std::{fs, os::unix::fs::MetadataExt, path::Path};

use crate::{AgentError, replay::DurableSecurityState, replay_test_support::Fixture};

#[test]
fn production_initializer_commits_genesis_and_runtime_rejects_coherent_reset() {
    let fixture = Fixture::new_uninitialized();
    let uid = fs::metadata(&fixture.state).expect("metadata").uid();
    DurableSecurityState::initialize_once(&fixture.state, &fixture.anchor, uid, "endpoint-a", 1)
        .expect("initialize");
    DurableSecurityState::open(&fixture.state, &fixture.anchor, uid, "endpoint-a", 1)
        .expect("runtime");
    retain_initialization_only(&fixture.state, true);
    retain_initialization_only(&fixture.anchor, false);
    assert!(matches!(
        DurableSecurityState::open(&fixture.state, &fixture.anchor, uid, "endpoint-a", 1),
        Err(AgentError::AuthorityRollback)
    ));
}

#[test]
fn runtime_open_durably_ratchets_the_signed_configuration_generation() {
    let fixture = Fixture::new_uninitialized();
    let uid = fs::metadata(&fixture.state).expect("metadata").uid();
    DurableSecurityState::initialize_once(&fixture.state, &fixture.anchor, uid, "endpoint-a", 1)
        .expect("initialize");
    DurableSecurityState::open(&fixture.state, &fixture.anchor, uid, "endpoint-a", 2)
        .expect("upgrade");
    assert!(matches!(
        DurableSecurityState::open(&fixture.state, &fixture.anchor, uid, "endpoint-a", 1),
        Err(AgentError::AuthorityRollback)
    ));
}

fn retain_initialization_only(root: &Path, state: bool) {
    for entry in fs::read_dir(root).expect("entries") {
        let path = entry.expect("entry").path();
        let name = path.file_name().expect("name").to_string_lossy();
        let keep = name == "binding.json"
            || name == "sealed.json"
            || (state && matches!(name.as_ref(), "ledger.lock" | "execution.lock"));
        if !keep {
            fs::remove_file(path).expect("remove committed state");
        }
    }
}
