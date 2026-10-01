use crate::{
    AgentError,
    replay_record::{self, AnchorRecord, Binding, StateRecord, Transaction},
    replay_scan::Entry,
    replay_scan_names,
};

pub(super) fn transaction(
    value: &Transaction,
    deployment: &str,
    generation: u64,
    ledger: &str,
) -> Result<(), AgentError> {
    let next = value
        .base_revision
        .checked_add(1)
        .ok_or(AgentError::AuthorityRollback)?;
    let base = if value.base_revision == 0 {
        value.base_state_digest.is_none() && value.base_anchor_digest.is_none()
    } else {
        value
            .base_state_digest
            .as_deref()
            .is_some_and(replay_record::valid_digest)
            && value
                .base_anchor_digest
                .as_deref()
                .is_some_and(replay_record::valid_digest)
    };
    let valid = value.schema == replay_record::TRANSACTION_SCHEMA
        && value.ledger_id == ledger
        && value.endpoint_deployment_id == deployment
        && (1..=generation).contains(&value.configuration_generation)
        && value.head.schema == replay_record::HEAD_SCHEMA
        && value.head.ledger_id == ledger
        && value.head.endpoint_deployment_id == deployment
        && value.head.configuration_generation == value.configuration_generation
        && value.head.revision == next
        && name_binds(&value.state_name, "state", next, &value.head.state_digest)
        && name_binds(
            &value.anchor_name,
            "anchor",
            next,
            &value.head.anchor_digest,
        )
        && replay_record::valid_digest(&value.head.state_digest)
        && replay_record::valid_digest(&value.head.anchor_digest)
        && base;
    valid.then_some(()).ok_or(AgentError::AuthorityRollback)
}

pub(super) fn base(
    binding: &Binding,
    generation: u64,
    transaction: &Transaction,
    states: &[Entry<StateRecord>],
    anchors: &[Entry<AnchorRecord>],
) -> Result<(), AgentError> {
    if transaction.base_revision == 0 {
        return (states.is_empty() && anchors.is_empty())
            .then_some(())
            .ok_or(AgentError::AuthorityRollback);
    }
    crate::replay_scan_validate::history(binding, generation, states, anchors)?;
    let state = states.last().ok_or(AgentError::AuthorityRollback)?;
    let anchor = anchors.last().ok_or(AgentError::AuthorityRollback)?;
    (state.value.revision == transaction.base_revision
        && transaction.configuration_generation >= state.value.configuration_generation
        && transaction.configuration_generation >= anchor.value.configuration_generation
        && Some(state.digest.as_str()) == transaction.base_state_digest.as_deref()
        && Some(anchor.digest.as_str()) == transaction.base_anchor_digest.as_deref())
    .then_some(())
    .ok_or(AgentError::AuthorityRollback)
}

fn name_binds(name: &str, prefix: &str, revision: u64, digest: &str) -> bool {
    replay_scan_names::parse_name(name, prefix).is_some_and(|(named_revision, named_digest)| {
        named_revision == revision && digest.strip_prefix("sha256:") == Some(&named_digest)
    })
}

pub(super) fn new_pair(
    binding: &Binding,
    generation: u64,
    transaction: &Transaction,
    state: Option<&Entry<StateRecord>>,
    anchor: Option<&Entry<AnchorRecord>>,
) -> Result<(), AgentError> {
    if let Some(state) = state {
        crate::replay_scan_validate::state_record(binding, generation, &state.value)?;
        if state.digest != transaction.head.state_digest
            || state.value.revision != transaction.head.revision
            || state.value.previous_state_digest != transaction.base_state_digest
        {
            return Err(AgentError::AuthorityRollback);
        }
    }
    if let Some(anchor) = anchor {
        crate::replay_scan_validate::anchor_record(
            binding,
            generation,
            &anchor.value,
            &transaction.head.state_digest,
        )?;
        if anchor.digest != transaction.head.anchor_digest
            || anchor.value.revision != transaction.head.revision
            || anchor.value.previous_anchor_digest != transaction.base_anchor_digest
        {
            return Err(AgentError::AuthorityRollback);
        }
    }
    Ok(())
}
