use crate::{
    AgentError,
    replay_file::PinnedDir,
    replay_record::{self, AnchorRecord, Binding, StateRecord},
};

pub(super) struct Entry<T> {
    pub name: String,
    pub digest: String,
    pub value: T,
}
pub(super) struct Snapshot {
    pub binding_digest: String,
    pub states: Vec<Entry<StateRecord>>,
    pub anchors: Vec<Entry<AnchorRecord>>,
}

impl Snapshot {
    pub fn current(&self) -> Option<&Entry<StateRecord>> {
        self.states.last()
    }
    pub fn current_anchor(&self) -> Option<&Entry<AnchorRecord>> {
        self.anchors.last()
    }
}

pub(super) fn scan(
    state: &PinnedDir,
    anchor: &PinnedDir,
    deployment: &str,
    generation: u64,
    ledger: &str,
) -> Result<Snapshot, AgentError> {
    let state_names = state.names()?;
    let anchor_names = anchor.names()?;
    crate::replay_scan_names::classify(&state_names, true)?;
    crate::replay_scan_names::classify(&anchor_names, false)?;
    let state_binding = state.read("binding.json")?;
    let anchor_binding = anchor.read("binding.json")?;
    if state_binding != anchor_binding {
        return Err(AgentError::AuthorityRollback);
    }
    let binding: Binding = crate::replay_scan_names::decode(&state_binding)?;
    crate::replay_scan_integrity::valid_binding(&binding, deployment, generation, ledger)?;
    let binding_digest = replay_record::digest(&state_binding);
    if !state_names.iter().any(|name| name == "sealed.json")
        || !anchor_names.iter().any(|name| name == "sealed.json")
    {
        return Err(AgentError::AuthorityRollback);
    }
    crate::replay_scan_integrity::verify_seals(state, anchor, &binding_digest)?;
    let committed = state_names.iter().any(|name| name == "committed.json");
    if committed != anchor_names.iter().any(|name| name == "committed.json") {
        return Err(AgentError::AuthorityRollback);
    }
    if !committed {
        if state_names != ["binding.json", "ledger.lock", "sealed.json"]
            || anchor_names != ["binding.json", "sealed.json"]
        {
            return Err(AgentError::AuthorityRollback);
        }
        return Ok(Snapshot {
            binding_digest,
            states: vec![],
            anchors: vec![],
        });
    }
    crate::replay_scan_integrity::verify_committed(state, anchor, &binding_digest)?;
    let states = crate::replay_scan_names::entries(state, &state_names, "state")?;
    let anchors = crate::replay_scan_names::entries(anchor, &anchor_names, "anchor")?;
    crate::replay_scan_validate::history(&binding, generation, &states, &anchors)?;
    crate::replay_scan_integrity::verify_heads(
        state,
        anchor,
        states.last().ok_or(AgentError::AuthorityRollback)?,
        anchors.last().ok_or(AgentError::AuthorityRollback)?,
    )?;
    Ok(Snapshot {
        binding_digest,
        states,
        anchors,
    })
}
