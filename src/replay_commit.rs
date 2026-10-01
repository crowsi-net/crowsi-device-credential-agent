use serde_json::Value;

use crate::{
    AgentError,
    replay_commit_fault::cut,
    replay_file::PinnedDir,
    replay_file_mutation::content_name,
    replay_record::{self, AnchorRecord, Committed, Head, StateRecord, Transaction},
    replay_scan::{self, Snapshot},
};

pub(super) fn commit(
    target: Target<'_>,
    snapshot: &Snapshot,
    payload: Value,
) -> Result<(), AgentError> {
    let Target {
        state,
        anchor,
        deployment,
        generation,
        ledger,
    } = target;
    if snapshot.current().is_some_and(|current| {
        current.value.payload == payload && current.value.configuration_generation == generation
    }) {
        return Ok(());
    }
    let revision = snapshot.current().map_or(Ok(1), |entry| {
        entry
            .value
            .revision
            .checked_add(1)
            .ok_or(AgentError::AuthorityRollback)
    })?;
    let payload_wire = replay_record::wire(&payload)?;
    let state_record = StateRecord {
        schema: replay_record::STATE_SCHEMA.into(),
        ledger_id: ledger.into(),
        endpoint_deployment_id: deployment.into(),
        configuration_generation: generation,
        revision,
        previous_state_digest: snapshot.current().map(|entry| entry.digest.clone()),
        payload_digest: replay_record::digest(&payload_wire),
        payload,
    };
    let state_wire = replay_record::wire(&state_record)?;
    let state_name = content_name("state", revision, &state_wire);
    let state_digest = replay_record::digest(&state_wire);
    let anchor_record = AnchorRecord {
        schema: replay_record::ANCHOR_SCHEMA.into(),
        ledger_id: ledger.into(),
        endpoint_deployment_id: deployment.into(),
        configuration_generation: generation,
        revision,
        state_digest: state_digest.clone(),
        previous_anchor_digest: snapshot.current_anchor().map(|entry| entry.digest.clone()),
    };
    let anchor_wire = replay_record::wire(&anchor_record)?;
    let anchor_name = content_name("anchor", revision, &anchor_wire);
    let anchor_digest = replay_record::digest(&anchor_wire);
    let head = Head {
        schema: replay_record::HEAD_SCHEMA.into(),
        ledger_id: ledger.into(),
        endpoint_deployment_id: deployment.into(),
        configuration_generation: generation,
        revision,
        state_digest,
        anchor_digest,
    };
    let transaction = Transaction {
        schema: replay_record::TRANSACTION_SCHEMA.into(),
        ledger_id: ledger.into(),
        endpoint_deployment_id: deployment.into(),
        configuration_generation: generation,
        base_revision: snapshot.current().map_or(0, |entry| entry.value.revision),
        base_state_digest: snapshot.current().map(|entry| entry.digest.clone()),
        base_anchor_digest: snapshot.current_anchor().map(|entry| entry.digest.clone()),
        state_name: state_name.clone(),
        anchor_name: anchor_name.clone(),
        head: head.clone(),
    };
    begin(state, anchor, &transaction)?;
    if snapshot.current().is_none() {
        mark_committed(state, anchor, &snapshot.binding_digest)?;
    }
    state.create(&state_name, &state_wire)?;
    state.sync()?;
    cut(5)?;
    anchor.create(&anchor_name, &anchor_wire)?;
    anchor.sync()?;
    cut(6)?;
    let head_wire = replay_record::wire(&head)?;
    state.replace("head.json", ".state-head.tmp", &head_wire)?;
    cut(7)?;
    anchor.replace("head.json", ".anchor-head.tmp", &head_wire)?;
    cut(8)?;
    state.remove("transaction.json")?;
    cut(9)?;
    anchor.remove("transaction.json")?;
    cut(10)?;
    if snapshot.states.len() == crate::replay_scan_names::HISTORY {
        state.remove(&snapshot.states[0].name)?;
        cut(11)?;
        anchor.remove(&snapshot.anchors[0].name)?;
    }
    replay_scan::scan(state, anchor, deployment, generation, ledger)?;
    Ok(())
}

pub(super) struct Target<'a> {
    pub state: &'a PinnedDir,
    pub anchor: &'a PinnedDir,
    pub deployment: &'a str,
    pub generation: u64,
    pub ledger: &'a str,
}

fn begin(state: &PinnedDir, anchor: &PinnedDir, value: &Transaction) -> Result<(), AgentError> {
    let wire = replay_record::wire(value)?;
    state.create("transaction.json", &wire)?;
    state.sync()?;
    cut(1)?;
    anchor.create("transaction.json", &wire)?;
    anchor.sync()
}

fn mark_committed(
    state: &PinnedDir,
    anchor: &PinnedDir,
    binding_digest: &str,
) -> Result<(), AgentError> {
    let wire = replay_record::wire(&Committed {
        schema: replay_record::COMMITTED_SCHEMA.into(),
        binding_digest: binding_digest.into(),
    })?;
    cut(2)?;
    state.create("committed.json", &wire)?;
    state.sync()?;
    cut(3)?;
    anchor.create("committed.json", &wire)?;
    anchor.sync()?;
    cut(4)
}
