use crate::{
    AgentError,
    replay_file::PinnedDir,
    replay_record::{self, Committed},
    replay_recover_transaction_io::{Context, HeadStatus, PendingPair},
};

pub(super) fn finish(
    context: &Context<'_>,
    status: (HeadStatus, HeadStatus),
    head: &[u8],
) -> Result<(), AgentError> {
    markers(context)?;
    finish_head(
        &context.layout.state,
        context.state_names,
        ".state-head.tmp",
        status.0,
        head,
    )?;
    finish_head(
        &context.layout.anchor,
        context.anchor_names,
        ".anchor-head.tmp",
        status.1,
        head,
    )?;
    remove_if(
        &context.layout.state,
        context.state_names,
        "transaction.json",
    )?;
    remove_if(
        &context.layout.anchor,
        context.anchor_names,
        "transaction.json",
    )
}

pub(super) fn rollback(
    context: &Context<'_>,
    status: (HeadStatus, HeadStatus),
    pending: PendingPair,
) -> Result<(), AgentError> {
    if status.0 != HeadStatus::Old
        || status.1 != HeadStatus::Old
        || context
            .state_names
            .iter()
            .any(|name| name == ".state-head.tmp")
        || context
            .anchor_names
            .iter()
            .any(|name| name == ".anchor-head.tmp")
    {
        return Err(AgentError::AuthorityRollback);
    }
    if let Some(value) = pending.state {
        context.layout.state.remove(&value.name)?;
    }
    if let Some(value) = pending.anchor {
        context.layout.anchor.remove(&value.name)?;
    }
    if context.transaction.base_revision == 0 {
        remove_if(&context.layout.state, context.state_names, "committed.json")?;
        remove_if(
            &context.layout.anchor,
            context.anchor_names,
            "committed.json",
        )?;
    }
    remove_if(
        &context.layout.state,
        context.state_names,
        "transaction.json",
    )?;
    remove_if(
        &context.layout.anchor,
        context.anchor_names,
        "transaction.json",
    )
}

fn markers(context: &Context<'_>) -> Result<(), AgentError> {
    let wire = replay_record::wire(&Committed {
        schema: replay_record::COMMITTED_SCHEMA.into(),
        binding_digest: context.binding.into(),
    })?;
    exact_or_create(
        &context.layout.state,
        context.state_names,
        "committed.json",
        &wire,
    )?;
    exact_or_create(
        &context.layout.anchor,
        context.anchor_names,
        "committed.json",
        &wire,
    )
}

fn exact_or_create(
    dir: &PinnedDir,
    names: &[String],
    name: &str,
    wire: &[u8],
) -> Result<(), AgentError> {
    if names.iter().any(|value| value == name) {
        if dir.read(name)? != wire {
            return Err(AgentError::AuthorityRollback);
        }
    } else {
        dir.create(name, wire)?;
        dir.sync()?;
    }
    Ok(())
}

fn finish_head(
    dir: &PinnedDir,
    names: &[String],
    temporary: &str,
    status: HeadStatus,
    wire: &[u8],
) -> Result<(), AgentError> {
    remove_if(dir, names, temporary)?;
    if status == HeadStatus::Old {
        dir.replace("head.json", temporary, wire)?;
    }
    Ok(())
}

fn remove_if(dir: &PinnedDir, names: &[String], name: &str) -> Result<(), AgentError> {
    if names.iter().any(|value| value == name) {
        dir.remove(name)?;
    }
    Ok(())
}
