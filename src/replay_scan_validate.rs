use crate::{
    AgentError,
    replay_record::{self, AnchorRecord, Binding, StateRecord},
    replay_scan::Entry,
    replay_scan_names::{HISTORY, parse_name},
};

pub(super) fn history(
    binding: &Binding,
    expected: u64,
    states: &[Entry<StateRecord>],
    anchors: &[Entry<AnchorRecord>],
) -> Result<(), AgentError> {
    history_limit(binding, expected, states, anchors, HISTORY)
}

pub(super) fn history_limit(
    binding: &Binding,
    expected: u64,
    states: &[Entry<StateRecord>],
    anchors: &[Entry<AnchorRecord>],
    maximum: usize,
) -> Result<(), AgentError> {
    if states.is_empty() || states.len() != anchors.len() || states.len() > maximum {
        return Err(AgentError::AuthorityRollback);
    }
    for index in 0..states.len() {
        let state = &states[index];
        let anchor = &anchors[index];
        let revision = parse_name(&state.name, "state")
            .ok_or(AgentError::AuthorityRollback)?
            .0;
        let anchor_revision = parse_name(&anchor.name, "anchor")
            .ok_or(AgentError::AuthorityRollback)?
            .0;
        if revision != anchor_revision
            || state.value.revision != revision
            || anchor.value.revision != revision
        {
            return Err(AgentError::AuthorityRollback);
        }
        if index > 0
            && revision
                != states[index - 1]
                    .value
                    .revision
                    .checked_add(1)
                    .ok_or(AgentError::AuthorityRollback)?
        {
            return Err(AgentError::AuthorityRollback);
        }
        state_record(binding, expected, &state.value)?;
        anchor_record(binding, expected, &anchor.value, &state.digest)?;
        chain(index, revision, states, anchors)?;
    }
    Ok(())
}

pub(super) fn state_record(
    binding: &Binding,
    expected: u64,
    value: &StateRecord,
) -> Result<(), AgentError> {
    let valid = value.schema == replay_record::STATE_SCHEMA
        && value.ledger_id == binding.ledger_id
        && value.endpoint_deployment_id == binding.endpoint_deployment_id
        && (binding.initial_configuration_generation..=expected)
            .contains(&value.configuration_generation)
        && replay_record::valid_digest(&value.payload_digest)
        && replay_record::digest(&replay_record::wire(&value.payload)?) == value.payload_digest;
    valid.then_some(()).ok_or(AgentError::AuthorityRollback)
}

pub(super) fn anchor_record(
    binding: &Binding,
    expected: u64,
    value: &AnchorRecord,
    state_digest: &str,
) -> Result<(), AgentError> {
    let valid = value.schema == replay_record::ANCHOR_SCHEMA
        && value.ledger_id == binding.ledger_id
        && value.endpoint_deployment_id == binding.endpoint_deployment_id
        && (binding.initial_configuration_generation..=expected)
            .contains(&value.configuration_generation)
        && value.state_digest == state_digest
        && replay_record::valid_digest(&value.state_digest);
    valid.then_some(()).ok_or(AgentError::AuthorityRollback)
}

fn chain(
    index: usize,
    revision: u64,
    states: &[Entry<StateRecord>],
    anchors: &[Entry<AnchorRecord>],
) -> Result<(), AgentError> {
    if index == 0 {
        let valid = if revision == 1 {
            states[0].value.previous_state_digest.is_none()
                && anchors[0].value.previous_anchor_digest.is_none()
        } else {
            states[0]
                .value
                .previous_state_digest
                .as_deref()
                .is_some_and(replay_record::valid_digest)
                && anchors[0]
                    .value
                    .previous_anchor_digest
                    .as_deref()
                    .is_some_and(replay_record::valid_digest)
        };
        return valid.then_some(()).ok_or(AgentError::AuthorityRollback);
    }
    (states[index].value.previous_state_digest.as_deref() == Some(&states[index - 1].digest)
        && anchors[index].value.previous_anchor_digest.as_deref()
            == Some(&anchors[index - 1].digest)
        && states[index].value.configuration_generation
            >= states[index - 1].value.configuration_generation
        && anchors[index].value.configuration_generation
            >= anchors[index - 1].value.configuration_generation)
        .then_some(())
        .ok_or(AgentError::AuthorityRollback)
}
