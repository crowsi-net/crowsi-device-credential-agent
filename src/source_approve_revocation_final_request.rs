use crowsi_credential_authority_contracts::{
    EndpointPreparedOperationV2, ManagementIntentV2, SignedAuthorityExchangeV1,
};
use ihat_identity_assertion_contracts::{
    AUTHORITY_REQUEST_SCHEMA, AuthorityCommand, AuthorityRequestV1, RevocationCeremonyStateDto,
    RevokeDeviceByRefCommand, RevokeSessionByRefCommand, decode_authority_request_strict,
};

use crate::AgentError;

pub(crate) fn build(
    prepared: &EndpointPreparedOperationV2,
    begun: &SignedAuthorityExchangeV1,
) -> Result<Option<AuthorityRequestV1>, AgentError> {
    let metadata = crate::source_approve_revocation_response_begin::metadata(prepared, begun)?;
    let independent = crate::source_approve_revocation_binding::independent(prepared)?;
    if independent {
        return (metadata.independent_approval_required
            && metadata.state == RevocationCeremonyStateDto::AwaitingIndependentApproval)
            .then_some(None)
            .ok_or(AgentError::AuthorityResponseInvalid);
    }
    if metadata.independent_approval_required
        || metadata.state != RevocationCeremonyStateDto::ReadyToFinalize
    {
        return Err(AgentError::AuthorityResponseInvalid);
    }
    let requirements = crate::source_approve_revocation_binding::requirements(prepared)?;
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
    let request = AuthorityRequestV1 {
        schema: AUTHORITY_REQUEST_SCHEMA.into(),
        request_id: crate::random_id::create("revocation-final-request")?,
        command,
        evidence: Vec::new(),
    };
    validate(prepared, begun, &request)?;
    strict(request).map(Some)
}

pub(crate) fn validate(
    prepared: &EndpointPreparedOperationV2,
    begun: &SignedAuthorityExchangeV1,
    request: &AuthorityRequestV1,
) -> Result<(), AgentError> {
    let metadata = crate::source_approve_revocation_response_begin::metadata(prepared, begun)?;
    let requirements = crate::source_approve_revocation_binding::requirements(prepared)?;
    let ready = !metadata.independent_approval_required
        && metadata.state == RevocationCeremonyStateDto::ReadyToFinalize;
    let exact = match (&prepared.intent, &request.command) {
        (
            ManagementIntentV2::DeviceRevocation {
                service_id,
                target_device_ref,
                expected_device_revocation_epoch,
                ..
            },
            AuthorityCommand::RevokeDeviceByRef(value),
        ) => {
            value.command_id == prepared.operation_id
                && value.service_id == *service_id
                && value.pairwise_subject == prepared.pairwise_subject
                && value.target_device_id == *target_device_ref
                && value.expected_device_epoch == *expected_device_revocation_epoch
                && value.authority_id == requirements.finalization_authority_id
        }
        (
            ManagementIntentV2::SessionRevocation {
                service_id,
                target_session_ref,
                expected_session_revocation_epoch,
                ..
            },
            AuthorityCommand::RevokeSessionByRef(value),
        ) => {
            value.command_id == prepared.operation_id
                && value.service_id == *service_id
                && value.pairwise_subject == prepared.pairwise_subject
                && value.session_ref == *target_session_ref
                && value.expected_epoch == *expected_session_revocation_epoch
                && value.authority_id == requirements.finalization_authority_id
        }
        _ => false,
    };
    (ready && request.evidence.is_empty() && exact)
        .then_some(())
        .ok_or(AgentError::RequestInvalid)
}

fn strict(value: AuthorityRequestV1) -> Result<AuthorityRequestV1, AgentError> {
    let wire = serde_json::to_vec(&value).map_err(|_| AgentError::RequestInvalid)?;
    let decoded = decode_authority_request_strict(&wire).map_err(|_| AgentError::RequestInvalid)?;
    (decoded == value)
        .then_some(decoded)
        .ok_or(AgentError::RequestInvalid)
}
