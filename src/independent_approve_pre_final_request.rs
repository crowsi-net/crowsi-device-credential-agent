use crowsi_credential_authority_contracts::{
    ENDPOINT_INDEPENDENT_REVOCATION_PRE_FINAL_REQUEST_SCHEMA,
    EndpointIndependentRevocationPreFinalRequestV1, RevocationIndependentPreFinalCeremonyV1,
    decode_endpoint_independent_revocation_pre_final_request_strict,
};

use crate::{AgentError, independent_approve_state_types::IndependentApproveResume};

pub(super) fn build(
    value: &IndependentApproveResume,
    request_id: String,
) -> Result<EndpointIndependentRevocationPreFinalRequestV1, AgentError> {
    let record = &value.approval;
    let request = EndpointIndependentRevocationPreFinalRequestV1 {
        schema: ENDPOINT_INDEPENDENT_REVOCATION_PRE_FINAL_REQUEST_SCHEMA.into(),
        request_id,
        operation_id: record.operation_id.clone(),
        expected_state_revision: expected_revision(record)?,
        approve_revocation_request: record.browser_request.clone(),
        prepared: value.lookup.response.prepared.clone(),
        selected_identity_exchange: value.selected_identity.clone(),
        begin_uv_exchange: value.selected_begin.clone(),
        finish_uv_exchange: record
            .finish_exchange
            .clone()
            .ok_or(AgentError::AuthorityRollback)?,
        accepted_identity_exchange: record
            .current_exchange
            .clone()
            .ok_or(AgentError::AuthorityRollback)?,
        revocation_ceremony: RevocationIndependentPreFinalCeremonyV1 {
            begin: crate::independent_approve_ceremony_context::begun(value)?.clone(),
            approval: record
                .approval_exchange
                .clone()
                .ok_or(AgentError::AuthorityRollback)?,
        },
    };
    strict(request)
}

fn expected_revision(
    value: &crate::independent_approve_state_types::IndependentApproveRecordV1,
) -> Result<u64, AgentError> {
    let crowsi_credential_authority_contracts::ManagementCommandV2::ApproveRevocation {
        expected_state_revision,
        ..
    } = &value.browser_request.command
    else {
        return Err(AgentError::AuthorityRollback);
    };
    Ok(*expected_state_revision)
}

fn strict(
    value: EndpointIndependentRevocationPreFinalRequestV1,
) -> Result<EndpointIndependentRevocationPreFinalRequestV1, AgentError> {
    let wire = serde_json::to_vec(&value).map_err(|_| AgentError::RequestInvalid)?;
    let decoded = decode_endpoint_independent_revocation_pre_final_request_strict(&wire)
        .map_err(|_| AgentError::RequestInvalid)?;
    (decoded == value)
        .then_some(decoded)
        .ok_or(AgentError::RequestInvalid)
}
