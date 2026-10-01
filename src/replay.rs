use serde::{Serialize, de::DeserializeOwned};
use std::path::Path;

use crate::{AgentError, replay_commit, replay_layout::Layout, replay_scan};

pub(crate) struct DurableLedger {
    layout: Layout,
    deployment: String,
    generation: u64,
    ledger: String,
}

impl DurableLedger {
    pub(crate) fn initialize_once(
        state_directory: &Path,
        anchor_directory: &Path,
        expected_uid: u32,
        endpoint_deployment_id: &str,
        configuration_generation: u64,
        ledger_id: &str,
    ) -> Result<(), AgentError> {
        if configuration_generation == 0
            || !crate::replay_namespace::identifier(endpoint_deployment_id)
            || !crate::replay_namespace::identifier(ledger_id)
        {
            return Err(AgentError::PathInvalid);
        }
        let layout = Layout::open(state_directory, anchor_directory, expected_uid)?;
        crate::replay_initialize::initialize_once(
            &layout,
            endpoint_deployment_id,
            configuration_generation,
            ledger_id,
        )
    }

    pub(crate) fn open(
        state_directory: &Path,
        anchor_directory: &Path,
        expected_uid: u32,
        endpoint_deployment_id: &str,
        configuration_generation: u64,
        ledger_id: &str,
    ) -> Result<Self, AgentError> {
        if configuration_generation == 0
            || !crate::replay_namespace::identifier(endpoint_deployment_id)
            || !crate::replay_namespace::identifier(ledger_id)
        {
            return Err(AgentError::PathInvalid);
        }
        let value = Self {
            layout: Layout::open(state_directory, anchor_directory, expected_uid)?,
            deployment: endpoint_deployment_id.into(),
            generation: configuration_generation,
            ledger: ledger_id.into(),
        };
        let guard = value.layout.lock()?;
        crate::replay_recover::recover(
            &value.layout,
            &value.deployment,
            value.generation,
            &value.ledger,
        )?;
        value.snapshot()?;
        guard.verify()?;
        drop(guard);
        Ok(value)
    }

    pub(crate) fn load<T: DeserializeOwned>(&self) -> Result<Option<T>, AgentError> {
        let guard = self.layout.lock()?;
        let snapshot = self.snapshot()?;
        let result = snapshot
            .current()
            .map(|entry| {
                serde_json::from_value(entry.value.payload.clone())
                    .map_err(|_| AgentError::AuthorityRollback)
            })
            .transpose()?;
        guard.verify()?;
        Ok(result)
    }

    pub(crate) fn update<T: DeserializeOwned + Serialize>(
        &self,
        transition: impl FnOnce(Option<&T>) -> Result<Option<T>, AgentError>,
    ) -> Result<(), AgentError> {
        let guard = self.layout.lock()?;
        let snapshot = self.snapshot()?;
        let current: Option<T> = snapshot
            .current()
            .map(|entry| {
                serde_json::from_value(entry.value.payload.clone())
                    .map_err(|_| AgentError::AuthorityRollback)
            })
            .transpose()?;
        if let Some(next) = transition(current.as_ref())? {
            let payload = serde_json::to_value(next).map_err(|_| AgentError::AuthorityRollback)?;
            replay_commit::commit(
                replay_commit::Target {
                    state: &self.layout.state,
                    anchor: &self.layout.anchor,
                    deployment: &self.deployment,
                    generation: self.generation,
                    ledger: &self.ledger,
                },
                &snapshot,
                payload,
            )?;
        }
        guard.verify()
    }

    pub(crate) fn exclusive<R>(
        &self,
        transition: impl FnOnce() -> Result<R, AgentError>,
    ) -> Result<R, AgentError> {
        let guard = self.layout.execution_lock()?;
        let result = transition();
        guard.verify()?;
        result
    }

    fn snapshot(&self) -> Result<replay_scan::Snapshot, AgentError> {
        replay_scan::scan(
            &self.layout.state,
            &self.layout.anchor,
            &self.deployment,
            self.generation,
            &self.ledger,
        )
    }
}

pub(crate) use crate::replay_security::DurableSecurityState;
