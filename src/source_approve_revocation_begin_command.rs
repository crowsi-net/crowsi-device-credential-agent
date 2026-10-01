use crowsi_credential_authority_contracts::{EndpointPreparedOperationV2, ManagementIntentV2};
use ihat_identity_assertion_contracts::{
    AuthorityCommand, BeginDeviceRevocationCommand, BeginSessionRevocationCommand,
    FreshAuthenticationDto,
};

use crate::AgentError;

pub(crate) fn build(
    prepared: &EndpointPreparedOperationV2,
    command_id: String,
    proof_id: String,
    authentication: FreshAuthenticationDto,
) -> Result<AuthorityCommand, AgentError> {
    let service = crate::source_approve_revocation_binding::service(&prepared.intent).to_owned();
    let command = match &prepared.intent {
        ManagementIntentV2::DeviceRevocation {
            target_device_ref,
            expected_device_revocation_epoch,
            ..
        } => AuthorityCommand::BeginDeviceRevocation(BeginDeviceRevocationCommand {
            command_id,
            finalize_command_id: prepared.operation_id.clone(),
            service_id: service,
            pairwise_subject: prepared.pairwise_subject.clone(),
            source_device_id: prepared.source_device_ref.clone(),
            source_session_ref: prepared.source_session_ref.clone(),
            target_device_id: target_device_ref.clone(),
            expected_device_epoch: *expected_device_revocation_epoch,
            identity_nonce: prepared.source_identity_nonce.clone(),
            sender_proof_id: proof_id,
            authentication,
        }),
        ManagementIntentV2::SessionRevocation {
            target_session_ref,
            expected_session_revocation_epoch,
            ..
        } => AuthorityCommand::BeginSessionRevocation(BeginSessionRevocationCommand {
            command_id,
            finalize_command_id: prepared.operation_id.clone(),
            service_id: service,
            pairwise_subject: prepared.pairwise_subject.clone(),
            source_device_id: prepared.source_device_ref.clone(),
            source_session_ref: prepared.source_session_ref.clone(),
            target_session_ref: target_session_ref.clone(),
            expected_session_epoch: *expected_session_revocation_epoch,
            identity_nonce: prepared.source_identity_nonce.clone(),
            sender_proof_id: proof_id,
            authentication,
        }),
        ManagementIntentV2::DeviceTransfer { .. } => return Err(AgentError::RequestInvalid),
    };
    Ok(command)
}
