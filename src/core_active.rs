use crowsi_credential_authority_contracts::{ManagementCommandV2, ManagementRequestV2};

use crate::{
    AgentError, VerifiedConfig, identity_provider::IdentityEvidenceProvider,
    replay::DurableSecurityState, transport::AuthorityTransport,
};

pub(crate) fn handle<T: AuthorityTransport, I: IdentityEvidenceProvider>(
    config: &VerifiedConfig,
    state: &DurableSecurityState,
    transport: &T,
    identity: &I,
    request: &ManagementRequestV2,
    now: u64,
) -> Option<Result<Vec<u8>, AgentError>> {
    if let Some(result) = crate::retired_request::handle(config, state, transport, request, now) {
        return Some(result);
    }
    let result = match &request.command {
        ManagementCommandV2::SourceOptions { .. } => {
            crate::source_options::handle(config, state, transport, identity, request, now)
        }
        ManagementCommandV2::SourceApprove { .. } => {
            crate::source_approve::handle(config, state, transport, identity, request, now)
        }
        ManagementCommandV2::TargetOptions { .. } | ManagementCommandV2::ApprovalOptions { .. } => {
            crate::actor_options::handle(config, state, transport, identity, request, now)
        }
        ManagementCommandV2::TargetApprove { .. } => {
            crate::target_approve::handle(config, state, transport, identity, request, now)
        }
        ManagementCommandV2::ApproveRevocation { .. } => {
            crate::independent_approve::handle(config, state, transport, identity, request, now)
        }
        ManagementCommandV2::Cancel { .. } => {
            crate::cancel::handle(config, state, transport, identity, request, now)
        }
        ManagementCommandV2::Reconcile { .. } => {
            crate::reconcile::handle(config, state, transport, identity, request, now)
        }
        _ => return None,
    };
    Some(result)
}
