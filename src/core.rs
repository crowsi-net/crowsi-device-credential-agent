use crowsi_credential_authority_contracts::{
    ManagementCommandV2, decode_management_request_strict,
};
use std::path::Path;

use crate::{
    AgentError, VerifiedConfig, identity_provider::IdentityEvidenceProvider,
    replay::DurableSecurityState, transport::AuthorityTransport,
};

pub struct AgentCore<T: AuthorityTransport, I: IdentityEvidenceProvider> {
    config: VerifiedConfig,
    transport: T,
    identity: I,
    state: DurableSecurityState,
}

impl<T: AuthorityTransport, I: IdentityEvidenceProvider> AgentCore<T, I> {
    #[cfg(feature = "test-support")]
    pub fn from_documents(
        config_wire: &[u8],
        root_trust_wire: &[u8],
        transport: T,
        identity: I,
        now_epoch_s: u64,
    ) -> Result<Self, AgentError> {
        let config = crate::config::verify_config(config_wire, root_trust_wire, now_epoch_s)?;
        let uid = crate::process_identity::effective_uid()?;
        Self::from_verified(config, transport, identity, uid)
    }

    pub(crate) fn from_verified(
        config: VerifiedConfig,
        transport: T,
        identity: I,
        expected_uid: u32,
    ) -> Result<Self, AgentError> {
        if transport.route_binding_sha256()? != config.0.authority_route.binding_sha256 {
            return Err(AgentError::ConfigInvalid);
        }
        crate::independent_approve_key::validate(&config.0, expected_uid)?;
        let state = DurableSecurityState::open(
            Path::new(&config.0.endpoint_state_directory),
            Path::new(&config.0.endpoint_anchor_directory),
            expected_uid,
            &config.0.endpoint_deployment_id,
            config.0.configuration_generation,
        )?;
        Ok(Self {
            config,
            transport,
            identity,
            state,
        })
    }

    pub fn handle(&self, wire: &[u8], now: u64) -> Result<Vec<u8>, AgentError> {
        self.state.exclusive(|| self.handle_exclusive(wire, now))
    }

    #[cfg(feature = "test-support")]
    pub fn operation_journal_bytes(&self) -> Result<usize, AgentError> {
        self.state.transaction_namespaces(|values| {
            let (_, _, journal) = crate::source_options_state::documents(values)?;
            let bytes = serde_json::to_vec(&journal)
                .map_err(|_| AgentError::AuthorityRollback)?
                .len();
            Ok((bytes, false))
        })
    }

    #[cfg(feature = "test-support")]
    pub fn cancel_retirement_state(
        &self,
        request: &str,
        operation: &str,
    ) -> Result<(bool, bool, bool), AgentError> {
        self.state.transaction_namespaces(|values| {
            let (_, _, journal) = crate::source_options_state::documents(values)?;
            let active = journal.cancellations.contains_key(operation);
            let indexed = journal.cancellation_index.contains_key(request);
            let retired = journal.retired_request_receipts.contains_key(request);
            Ok(((active, indexed, retired), false))
        })
    }

    fn handle_exclusive(&self, wire: &[u8], now: u64) -> Result<Vec<u8>, AgentError> {
        let request =
            decode_management_request_strict(wire).map_err(|_| AgentError::RequestInvalid)?;
        let route = command_route(&request.command);
        crate::core_validation::validate_service(
            &request,
            &self.config.0.management_projection_trust.service_id,
        )?;
        if let Some(result) = crate::core_active::handle(
            &self.config,
            &self.state,
            &self.transport,
            &self.identity,
            &request,
            now,
        ) {
            return result;
        }
        let identity = self.identity.current_identity(&self.config.0, now)?;
        crate::core_identity::verify_and_observe(&self.config, &self.state, &identity, now)?;
        let envelope = crate::core_envelope::passive(request.clone(), identity)?;
        let envelope = serde_json::to_vec(&envelope).map_err(|_| AgentError::RequestInvalid)?;
        let response = self.transport.exchange(route, &envelope, now)?;
        let projection = crate::core_projection::decode_and_verify(
            &self.config,
            &self.state,
            &request,
            &response,
            now,
        )?;
        self.state.observe_management_projection(&projection, now)?;
        serde_json::to_vec(&projection).map_err(|_| AgentError::ResponseInvalid)
    }
}

pub(crate) fn initialize_state(
    config: &VerifiedConfig,
    expected_uid: u32,
) -> Result<(), AgentError> {
    DurableSecurityState::initialize_once(
        Path::new(&config.0.endpoint_state_directory),
        Path::new(&config.0.endpoint_anchor_directory),
        expected_uid,
        &config.0.endpoint_deployment_id,
        config.0.configuration_generation,
    )
}

pub(crate) const fn command_route(value: &ManagementCommandV2) -> &'static str {
    match value {
        ManagementCommandV2::Snapshot { .. } => "snapshot",
        ManagementCommandV2::SourceOptions { .. } => "source-options",
        ManagementCommandV2::SourceApprove { .. } => "source-approve",
        ManagementCommandV2::PendingList { .. } => "pending",
        ManagementCommandV2::TargetOptions { .. } => "target-options",
        ManagementCommandV2::TargetApprove { .. } => "target-approve",
        ManagementCommandV2::ApprovalOptions { .. } => "approval-options",
        ManagementCommandV2::ApproveRevocation { .. } => "approve-revocation",
        ManagementCommandV2::Cancel { .. } => "cancel",
        ManagementCommandV2::Reconcile { .. } => "reconcile",
    }
}
