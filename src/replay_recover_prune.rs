use crate::{
    AgentError,
    replay_layout::Layout,
    replay_record::{AnchorRecord, Binding, StateRecord},
    replay_scan::Entry,
    replay_scan_names::{self, HISTORY},
};

pub(super) fn recover(
    layout: &Layout,
    deployment: &str,
    generation: u64,
    ledger: &str,
) -> Result<(), AgentError> {
    let state_names = layout.state.names()?;
    let anchor_names = layout.anchor.names()?;
    if !state_names.iter().any(|name| name == "committed.json")
        && !anchor_names.iter().any(|name| name == "committed.json")
    {
        return Ok(());
    }
    replay_scan_names::classify(&state_names, true)?;
    replay_scan_names::classify(&anchor_names, false)?;
    let binding_wire = layout.state.read("binding.json")?;
    if binding_wire != layout.anchor.read("binding.json")? {
        return Err(AgentError::AuthorityRollback);
    }
    let binding: Binding = replay_scan_names::decode(&binding_wire)?;
    crate::replay_scan_integrity::valid_binding(&binding, deployment, generation, ledger)?;
    let digest = crate::replay_record::digest(&binding_wire);
    crate::replay_scan_integrity::verify_seals(&layout.state, &layout.anchor, &digest)?;
    crate::replay_scan_integrity::verify_committed(&layout.state, &layout.anchor, &digest)?;
    let mut states: Vec<Entry<StateRecord>> =
        replay_scan_names::entries_limit(&layout.state, &state_names, "state", HISTORY + 1)?;
    let mut anchors: Vec<Entry<AnchorRecord>> =
        replay_scan_names::entries_limit(&layout.anchor, &anchor_names, "anchor", HISTORY + 1)?;
    align_partial_prune(layout, &mut states, &mut anchors)?;
    if states.len() != anchors.len() {
        return Err(AgentError::AuthorityRollback);
    }
    crate::replay_scan_validate::history_limit(
        &binding,
        generation,
        &states,
        &anchors,
        HISTORY + 1,
    )?;
    crate::replay_scan_integrity::verify_heads(
        &layout.state,
        &layout.anchor,
        states.last().ok_or(AgentError::AuthorityRollback)?,
        anchors.last().ok_or(AgentError::AuthorityRollback)?,
    )?;
    if states.len() == HISTORY + 1 {
        layout.state.remove(&states[0].name)?;
        layout.anchor.remove(&anchors[0].name)?;
    }
    Ok(())
}

fn align_partial_prune(
    layout: &Layout,
    states: &mut Vec<Entry<StateRecord>>,
    anchors: &mut Vec<Entry<AnchorRecord>>,
) -> Result<(), AgentError> {
    if states.len() + 1 == anchors.len() && aligned(states, &anchors[1..]) {
        layout.anchor.remove(&anchors[0].name)?;
        anchors.remove(0);
    } else if anchors.len() + 1 == states.len() && aligned(&states[1..], anchors) {
        layout.state.remove(&states[0].name)?;
        states.remove(0);
    }
    Ok(())
}

fn aligned(states: &[Entry<StateRecord>], anchors: &[Entry<AnchorRecord>]) -> bool {
    states.len() == anchors.len()
        && states.iter().zip(anchors).all(|(state, anchor)| {
            state.value.revision == anchor.value.revision
                && anchor.value.state_digest == state.digest
        })
}
