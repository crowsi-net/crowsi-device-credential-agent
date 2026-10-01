use crowsi_credential_authority_contracts::{
    EndpointPreparedOperationV2, ManagementIntentV2, SignedAuthorityExchangeV1,
};
use ihat_identity_assertion_contracts::{
    AUTHORITY_REQUEST_SCHEMA, AuthorityCommand, AuthorityRequestV1, RevokeDeviceByRefCommand,
    RevokeSessionByRefCommand,
};

use crate::AgentError;

pub(crate) fn build(
    approval_key_id: &str,
    approval_public_key_hex: &str,
    prepared: &EndpointPreparedOperationV2,
    begun: &SignedAuthorityExchangeV1,
    current: &SignedAuthorityExchangeV1,
    approval: &SignedAuthorityExchangeV1,
) -> Result<AuthorityRequestV1, AgentError> {
    crate::independent_approve_response_approval::validate(
        approval_key_id,
        approval_public_key_hex,
        prepared,
        begun,
        current,
        approval,
    )?;
    let requirements = prepared
        .revocation
        .as_ref()
        .ok_or(AgentError::RequestInvalid)?;
    let command = match &prepared.intent {
        ManagementIntentV2::DeviceRevocation {
            service_id,
            target_device_ref,
            expected_device_revocation_epoch,
            ..
        } => AuthorityCommand::RevokeDeviceByRef(RevokeDeviceByRefCommand {
            command_id: prepared.operation_id.clone(),
            service_id: service_id.clone(),
            pairwise_subject: prepared.pairwise_subject.clone(),
            target_device_id: target_device_ref.clone(),
            expected_device_epoch: *expected_device_revocation_epoch,
            authority_id: requirements.finalization_authority_id.clone(),
        }),
        ManagementIntentV2::SessionRevocation {
            service_id,
            target_session_ref,
            expected_session_revocation_epoch,
            ..
        } => AuthorityCommand::RevokeSessionByRef(RevokeSessionByRefCommand {
            command_id: prepared.operation_id.clone(),
            service_id: service_id.clone(),
            pairwise_subject: prepared.pairwise_subject.clone(),
            session_ref: target_session_ref.clone(),
            expected_epoch: *expected_session_revocation_epoch,
            authority_id: requirements.finalization_authority_id.clone(),
        }),
        ManagementIntentV2::DeviceTransfer { .. } => return Err(AgentError::RequestInvalid),
    };
    let value = AuthorityRequestV1 {
        schema: AUTHORITY_REQUEST_SCHEMA.into(),
        request_id: crate::independent_approve_final_request_validation::request_id(
            prepared, begun, approval,
        )?,
        command,
        evidence: Vec::new(),
    };
    crate::independent_approve_final_request_validation::validate(
        approval_key_id,
        approval_public_key_hex,
        prepared,
        begun,
        current,
        approval,
        &value,
    )?;
    crate::independent_approve_final_request_validation::strict(value)
}
