use std::path::Path;

use crate::{AgentError, management_state, replay::DurableLedger};

pub(crate) struct DurableSecurityState {
    ledger: DurableLedger,
}

impl DurableSecurityState {
    pub(crate) fn initialize_once(
        state_directory: &Path,
        anchor_directory: &Path,
        expected_uid: u32,
        endpoint_deployment_id: &str,
        configuration_generation: u64,
    ) -> Result<(), AgentError> {
        DurableLedger::initialize_once(
            state_directory,
            anchor_directory,
            expected_uid,
            endpoint_deployment_id,
            configuration_generation,
            "endpoint-security-state",
        )?;
        let ledger = DurableLedger::open(
            state_directory,
            anchor_directory,
            expected_uid,
            endpoint_deployment_id,
            configuration_generation,
            "endpoint-security-state",
        )?;
        ledger.transaction_namespaces(|_| Ok(((), true)))
    }
    pub(crate) fn open(
        state_directory: &Path,
        anchor_directory: &Path,
        expected_uid: u32,
        endpoint_deployment_id: &str,
        configuration_generation: u64,
    ) -> Result<Self, AgentError> {
        let ledger = DurableLedger::open(
            state_directory,
            anchor_directory,
            expected_uid,
            endpoint_deployment_id,
            configuration_generation,
            "endpoint-security-state",
        )?;
        ledger.verify_namespaces()?;
        ledger.transaction_namespaces(|_| Ok(((), true)))?;
        Ok(Self { ledger })
    }
    pub(crate) fn observe_management_projection(
        &self,
        value: &crowsi_credential_authority_contracts::ManagementProjectionV2,
        now: u64,
    ) -> Result<(), AgentError> {
        self.transaction_namespaces(|values| {
            let (mut prepared, mut fresh, mut journal) =
                crate::source_options_state::documents(values)?;
            crate::operation_artifact_cleanup::terminal_projection(
                value,
                &mut prepared,
                &mut fresh,
                &mut journal,
                now,
            )?;
            crate::source_options_state::validate(&prepared, &fresh, &journal)?;
            management_state::observe_in_transaction(values, value)?;
            values.put("prepared-operation", &prepared)?;
            values.put("fresh-uv-attempt", &fresh)?;
            values.put("operation-journal", &journal)?;
            Ok(((), true))
        })
    }
    pub(crate) fn management_snapshot(
        &self,
        now: u64,
    ) -> Result<crate::management_state::CachedManagementSnapshot, AgentError> {
        management_state::snapshot(&self.ledger, now)
    }
    pub(crate) fn identity_locator(&self) -> crate::identity_locator_io::IdentityLocatorStore<'_> {
        crate::identity_locator_io::IdentityLocatorStore::new(&self.ledger)
    }
    pub(crate) fn transaction_namespaces<R>(
        &self,
        transition: impl FnOnce(
            &mut crate::replay_namespace::SecurityNamespaces,
        ) -> Result<(R, bool), AgentError>,
    ) -> Result<R, AgentError> {
        self.ledger.transaction_namespaces(transition)
    }
    pub(crate) fn exclusive<R>(
        &self,
        transition: impl FnOnce() -> Result<R, AgentError>,
    ) -> Result<R, AgentError> {
        self.ledger.exclusive(transition)
    }
}
