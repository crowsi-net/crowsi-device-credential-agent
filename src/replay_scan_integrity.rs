use crate::{
    AgentError,
    replay_file::PinnedDir,
    replay_record::{self, AnchorRecord, Binding, Committed, Head, Seal, StateRecord},
    replay_scan::Entry,
    replay_scan_names::decode,
};

pub(super) fn verify_seals(
    state: &PinnedDir,
    anchor: &PinnedDir,
    binding_digest: &str,
) -> Result<(), AgentError> {
    let state_wire = state.read("sealed.json")?;
    let anchor_wire = anchor.read("sealed.json")?;
    let seal: Seal = decode(&state_wire)?;
    (state_wire == anchor_wire
        && seal.schema == replay_record::SEAL_SCHEMA
        && seal.binding_digest == binding_digest)
        .then_some(())
        .ok_or(AgentError::AuthorityRollback)
}

pub(super) fn verify_committed(
    state: &PinnedDir,
    anchor: &PinnedDir,
    binding_digest: &str,
) -> Result<(), AgentError> {
    let state_wire = state.read("committed.json")?;
    let anchor_wire = anchor.read("committed.json")?;
    let marker: Committed = decode(&state_wire)?;
    (state_wire == anchor_wire
        && marker.schema == replay_record::COMMITTED_SCHEMA
        && marker.binding_digest == binding_digest)
        .then_some(())
        .ok_or(AgentError::AuthorityRollback)
}

pub(super) fn verify_heads(
    state: &PinnedDir,
    anchor: &PinnedDir,
    latest_state: &Entry<StateRecord>,
    latest_anchor: &Entry<AnchorRecord>,
) -> Result<(), AgentError> {
    let state_wire = state.read("head.json")?;
    let anchor_wire = anchor.read("head.json")?;
    let head: Head = decode(&state_wire)?;
    let valid = state_wire == anchor_wire
        && head.schema == replay_record::HEAD_SCHEMA
        && head.ledger_id == latest_state.value.ledger_id
        && head.endpoint_deployment_id == latest_state.value.endpoint_deployment_id
        && head.configuration_generation == latest_state.value.configuration_generation
        && head.revision == latest_state.value.revision
        && head.state_digest == latest_state.digest
        && head.anchor_digest == latest_anchor.digest;
    valid.then_some(()).ok_or(AgentError::AuthorityRollback)
}

pub(super) fn valid_binding(
    value: &Binding,
    deployment: &str,
    generation: u64,
    ledger: &str,
) -> Result<(), AgentError> {
    (value.schema == replay_record::BINDING_SCHEMA
        && value.ledger_id == ledger
        && value.endpoint_deployment_id == deployment
        && value.initial_configuration_generation > 0
        && value.initial_configuration_generation <= generation)
        .then_some(())
        .ok_or(AgentError::AuthorityRollback)
}
