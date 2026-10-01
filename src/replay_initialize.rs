use crate::{
    AgentError,
    replay_file::PinnedDir,
    replay_layout::Layout,
    replay_record::{self, Binding, Seal},
};

pub(super) fn initialize_once(
    layout: &Layout,
    deployment: &str,
    generation: u64,
    ledger: &str,
) -> Result<(), AgentError> {
    let guard = layout.lock()?;
    let binding = Binding {
        schema: replay_record::BINDING_SCHEMA.into(),
        ledger_id: ledger.into(),
        endpoint_deployment_id: deployment.into(),
        initial_configuration_generation: generation,
    };
    let binding_wire = replay_record::wire(&binding)?;
    let seal_wire = replay_record::wire(&Seal {
        schema: replay_record::SEAL_SCHEMA.into(),
        binding_digest: replay_record::digest(&binding_wire),
    })?;
    exact_or_create(&layout.state, "binding.json", &binding_wire, true)?;
    exact_or_create(&layout.anchor, "binding.json", &binding_wire, false)?;
    exact_or_create(&layout.state, "sealed.json", &seal_wire, true)?;
    exact_or_create(&layout.anchor, "sealed.json", &seal_wire, false)?;
    crate::replay_recover::recover(layout, deployment, generation, ledger)?;
    crate::replay_scan::scan(
        &layout.state,
        &layout.anchor,
        deployment,
        generation,
        ledger,
    )?;
    guard.verify()
}

fn exact_or_create(
    dir: &PinnedDir,
    name: &str,
    expected: &[u8],
    state: bool,
) -> Result<(), AgentError> {
    let names = dir.names()?;
    if names.iter().any(|value| value == name) {
        if dir.read(name)? != expected {
            return Err(AgentError::AuthorityRollback);
        }
    } else {
        let allowed = names.iter().all(|value| {
            value == "binding.json" || value == "sealed.json" || (state && value == "ledger.lock")
        });
        if !allowed {
            return Err(AgentError::AuthorityRollback);
        }
        dir.create(name, expected)?;
        dir.sync()?;
    }
    Ok(())
}
