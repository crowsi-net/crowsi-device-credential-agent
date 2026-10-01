use crate::{
    AgentError,
    replay_file::PinnedDir,
    replay_layout::Layout,
    replay_record::{self, AnchorRecord, Head, StateRecord, Transaction},
    replay_scan::Entry,
};

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum HeadStatus {
    Old,
    New,
}

pub(super) struct Context<'a> {
    pub layout: &'a Layout,
    pub state_names: &'a [String],
    pub anchor_names: &'a [String],
    pub transaction: &'a Transaction,
    pub binding: &'a str,
}
pub(super) struct History<'a> {
    pub states: &'a [Entry<StateRecord>],
    pub anchors: &'a [Entry<AnchorRecord>],
}
pub(super) struct PendingPair {
    pub state: Option<Entry<StateRecord>>,
    pub anchor: Option<Entry<AnchorRecord>>,
}

pub(super) fn resolve(
    context: Context<'_>,
    history: History<'_>,
    pending: PendingPair,
) -> Result<(), AgentError> {
    let old_head = base_head(history.states, history.anchors)?;
    let new_head = replay_record::wire(&context.transaction.head)?;
    let state_status = head_status(
        &context.layout.state,
        context.state_names,
        old_head.as_deref(),
        &new_head,
    )?;
    let anchor_status = head_status(
        &context.layout.anchor,
        context.anchor_names,
        old_head.as_deref(),
        &new_head,
    )?;
    temporary(
        &context.layout.state,
        context.state_names,
        ".state-head.tmp",
        &new_head,
    )?;
    temporary(
        &context.layout.anchor,
        context.anchor_names,
        ".anchor-head.tmp",
        &new_head,
    )?;
    if pending.state.is_some() && pending.anchor.is_some() {
        crate::replay_recover_transaction_finish::finish(
            &context,
            (state_status, anchor_status),
            &new_head,
        )
    } else {
        crate::replay_recover_transaction_finish::rollback(
            &context,
            (state_status, anchor_status),
            pending,
        )
    }
}

fn base_head(
    states: &[Entry<StateRecord>],
    anchors: &[Entry<AnchorRecord>],
) -> Result<Option<Vec<u8>>, AgentError> {
    let Some(state) = states.last() else {
        return Ok(None);
    };
    let anchor = anchors.last().ok_or(AgentError::AuthorityRollback)?;
    replay_record::wire(&Head {
        schema: replay_record::HEAD_SCHEMA.into(),
        ledger_id: state.value.ledger_id.clone(),
        endpoint_deployment_id: state.value.endpoint_deployment_id.clone(),
        configuration_generation: state.value.configuration_generation,
        revision: state.value.revision,
        state_digest: state.digest.clone(),
        anchor_digest: anchor.digest.clone(),
    })
    .map(Some)
}

fn head_status(
    dir: &PinnedDir,
    names: &[String],
    old: Option<&[u8]>,
    new: &[u8],
) -> Result<HeadStatus, AgentError> {
    if !names.iter().any(|name| name == "head.json") {
        return old
            .is_none()
            .then_some(HeadStatus::Old)
            .ok_or(AgentError::AuthorityRollback);
    }
    let wire = dir.read("head.json")?;
    if wire == new {
        Ok(HeadStatus::New)
    } else if old == Some(&wire) {
        Ok(HeadStatus::Old)
    } else {
        Err(AgentError::AuthorityRollback)
    }
}

fn temporary(
    dir: &PinnedDir,
    names: &[String],
    name: &str,
    expected: &[u8],
) -> Result<(), AgentError> {
    if names.iter().any(|value| value == name) && dir.read(name)? != expected {
        return Err(AgentError::AuthorityRollback);
    }
    Ok(())
}
