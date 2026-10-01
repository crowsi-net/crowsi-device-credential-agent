use crate::{AgentError, replay_layout::Layout};

pub(super) fn recover(
    layout: &Layout,
    deployment: &str,
    generation: u64,
    ledger: &str,
) -> Result<(), AgentError> {
    layout.verify()?;
    let state = layout.state.names()?;
    let anchor = layout.anchor.names()?;
    let transaction = state.iter().any(|name| name == "transaction.json")
        || anchor.iter().any(|name| name == "transaction.json");
    let temporary = state.iter().any(|name| name == ".state-head.tmp")
        || anchor.iter().any(|name| name == ".anchor-head.tmp");
    if temporary && !transaction {
        return Err(AgentError::AuthorityRollback);
    }
    if transaction {
        crate::replay_recover_transaction::recover(layout, deployment, generation, ledger)?;
    }
    crate::replay_recover_prune::recover(layout, deployment, generation, ledger)
}
