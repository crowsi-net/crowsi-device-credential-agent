use crate::{
    AgentError,
    replay_layout::Layout,
    replay_record::{self, AnchorRecord, Binding, StateRecord, Transaction},
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
    allowed(&state_names, true)?;
    allowed(&anchor_names, false)?;
    let wire = transaction_wire(layout, &state_names, &anchor_names)?;
    let transaction: Transaction = replay_scan_names::decode(&wire)?;
    let binding_wire = layout.state.read("binding.json")?;
    if binding_wire != layout.anchor.read("binding.json")? {
        return Err(AgentError::AuthorityRollback);
    }
    let binding: Binding = replay_scan_names::decode(&binding_wire)?;
    crate::replay_scan_integrity::valid_binding(&binding, deployment, generation, ledger)?;
    let binding_digest = replay_record::digest(&binding_wire);
    crate::replay_scan_integrity::verify_seals(&layout.state, &layout.anchor, &binding_digest)?;
    crate::replay_recover_validation::transaction(&transaction, deployment, generation, ledger)?;
    if transaction.base_revision > 0 {
        crate::replay_scan_integrity::verify_committed(
            &layout.state,
            &layout.anchor,
            &binding_digest,
        )?;
    }
    let mut states: Vec<Entry<StateRecord>> =
        replay_scan_names::entries_limit(&layout.state, &state_names, "state", HISTORY + 1)?;
    let mut anchors: Vec<Entry<AnchorRecord>> =
        replay_scan_names::entries_limit(&layout.anchor, &anchor_names, "anchor", HISTORY + 1)?;
    let state_new = take_new(&mut states, &transaction.state_name);
    let anchor_new = take_new(&mut anchors, &transaction.anchor_name);
    crate::replay_recover_validation::base(&binding, generation, &transaction, &states, &anchors)?;
    crate::replay_recover_validation::new_pair(
        &binding,
        generation,
        &transaction,
        state_new.as_ref(),
        anchor_new.as_ref(),
    )?;
    crate::replay_recover_transaction_io::resolve(
        crate::replay_recover_transaction_io::Context {
            layout,
            state_names: &state_names,
            anchor_names: &anchor_names,
            transaction: &transaction,
            binding: &binding_digest,
        },
        crate::replay_recover_transaction_io::History {
            states: &states,
            anchors: &anchors,
        },
        crate::replay_recover_transaction_io::PendingPair {
            state: state_new,
            anchor: anchor_new,
        },
    )
}

fn allowed(names: &[String], state: bool) -> Result<(), AgentError> {
    let filtered: Vec<_> = names
        .iter()
        .filter(|name| {
            name.as_str() != "transaction.json"
                && name.as_str() != ".state-head.tmp"
                && name.as_str() != ".anchor-head.tmp"
        })
        .cloned()
        .collect();
    if (state && names.iter().any(|name| name == ".anchor-head.tmp"))
        || (!state && names.iter().any(|name| name == ".state-head.tmp"))
    {
        return Err(AgentError::AuthorityRollback);
    }
    replay_scan_names::classify(&filtered, state)
}

fn transaction_wire(
    layout: &Layout,
    state: &[String],
    anchor: &[String],
) -> Result<Vec<u8>, AgentError> {
    let left = state
        .iter()
        .any(|name| name == "transaction.json")
        .then(|| layout.state.read("transaction.json"))
        .transpose()?;
    let right = anchor
        .iter()
        .any(|name| name == "transaction.json")
        .then(|| layout.anchor.read("transaction.json"))
        .transpose()?;
    match (left, right) {
        (Some(a), Some(b)) if a == b => Ok(a),
        (Some(a), None) | (None, Some(a)) => Ok(a),
        _ => Err(AgentError::AuthorityRollback),
    }
}

fn take_new<T>(entries: &mut Vec<Entry<T>>, name: &str) -> Option<Entry<T>> {
    entries
        .iter()
        .position(|entry| entry.name == name)
        .map(|index| entries.remove(index))
}
