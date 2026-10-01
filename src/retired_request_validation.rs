use crowsi_credential_authority_contracts::{
    EndpointManagementEvidenceV2, ManagementProjectionBodyV2,
    decode_endpoint_management_envelope_strict, decode_management_projection_strict,
    management_command_digest,
};

use crate::{
    AgentError,
    retired_request_types::{RetiredRefreshMaterialV1, RetiredRequestReceiptV1},
    source_options_state_types::OperationJournalV1,
};

pub(super) fn all(journal: &OperationJournalV1) -> Result<(), AgentError> {
    let material = crate::retired_request_material::bytes(journal)?;
    let exact = journal.retired_request_receipts.len() <= 32
        && material <= 32_768
        && journal
            .retired_request_receipts
            .iter()
            .all(|(request, value)| record(request, value).is_ok());
    exact.then_some(()).ok_or(AgentError::AuthorityRollback)
}

fn record(request: &str, value: &RetiredRequestReceiptV1) -> Result<(), AgentError> {
    let base = crate::validation::id(request, 128)
        && crate::validation::hex_key(&value.browser_request_digest_sha256)
        && crate::validation::hex_key(&value.operation_id)
        && route(&value.route)
        && value.retired_at_epoch_s > 0
        && value.retired_at_epoch_s.checked_add(600) == Some(value.retain_until_epoch_s)
        && value.refresh_until_epoch_s == value.retain_until_epoch_s;
    let material = value.refresh_material.is_some();
    let raw = value.response_json.is_some();
    let typed = value.response.is_some();
    let refresh_only = matches!(
        value.refresh_material.as_ref(),
        Some(RetiredRefreshMaterialV1::CancelEnvelope(_))
            | Some(RetiredRefreshMaterialV1::CancelCleanupComplete(_))
    );
    let shape = if refresh_only {
        material && !raw && !typed
    } else {
        material == raw && raw == typed
    };
    if !base || !shape {
        return Err(AgentError::AuthorityRollback);
    }
    refresh(request, value)?;
    response(request, value)
}

fn refresh(request: &str, value: &RetiredRequestReceiptV1) -> Result<(), AgentError> {
    let Some(material) = &value.refresh_material else {
        return Ok(());
    };
    match material {
        RetiredRefreshMaterialV1::ManagementEnvelope(material) => {
            management(request, value, &material.route, &material.wire)
        }
        RetiredRefreshMaterialV1::CancelEnvelope(material) => {
            crate::retired_request_validation_cancel::exact(
                request,
                value,
                &material.wire,
                &material.expected_body,
                None,
            )
        }
        RetiredRefreshMaterialV1::CancelCleanupComplete(material) => {
            crate::retired_request_validation_cancel::exact(
                request,
                value,
                &material.wire,
                &material.expected_body,
                Some(material),
            )
        }
        RetiredRefreshMaterialV1::RevocationFinalize(material) => {
            crate::retired_request_validation_finalize::source(request, value, &material.wire)
        }
        RetiredRefreshMaterialV1::IndependentRevocationFinalize(material) => {
            crate::retired_request_validation_finalize::independent(request, value, &material.wire)
        }
    }
}

pub(super) fn management(
    request: &str,
    value: &RetiredRequestReceiptV1,
    route: &str,
    wire: &str,
) -> Result<(), AgentError> {
    let decoded = decode_endpoint_management_envelope_strict(wire.as_bytes())
        .map_err(|_| AgentError::AuthorityRollback)?;
    let digest = management_command_digest(&decoded.browser_request)
        .map_err(|_| AgentError::AuthorityRollback)?;
    let exact = value.route == route
        && crate::core::command_route(&decoded.browser_request.command) == route
        && decoded.browser_request.request_id == request
        && digest == value.browser_request_digest_sha256
        && prepared_operation(&decoded.evidence) == Some(value.operation_id.as_str());
    exact.then_some(()).ok_or(AgentError::AuthorityRollback)
}

fn prepared_operation(value: &EndpointManagementEvidenceV2) -> Option<&str> {
    match value {
        EndpointManagementEvidenceV2::Passive { .. } => None,
        EndpointManagementEvidenceV2::SourceOptions { prepared, .. }
        | EndpointManagementEvidenceV2::SourceApprove { prepared, .. }
        | EndpointManagementEvidenceV2::ActorOptions { prepared, .. }
        | EndpointManagementEvidenceV2::TargetApprove { prepared, .. }
        | EndpointManagementEvidenceV2::IndependentApprove { prepared, .. }
        | EndpointManagementEvidenceV2::Cancel { prepared, .. }
        | EndpointManagementEvidenceV2::Reconcile { prepared, .. } => Some(&prepared.operation_id),
    }
}

fn response(request: &str, value: &RetiredRequestReceiptV1) -> Result<(), AgentError> {
    let Some(wire) = value.response_json.as_deref() else {
        return Ok(());
    };
    let decoded = decode_management_projection_strict(wire.as_bytes())
        .map_err(|_| AgentError::AuthorityRollback)?;
    let operation = matches!(&decoded.body, ManagementProjectionBodyV2::Operation { operation }
        if operation.operation_id == value.operation_id);
    (value.response.as_ref() == Some(&decoded)
        && decoded.request_id == request
        && decoded.command_digest_sha256 == value.browser_request_digest_sha256
        && operation)
        .then_some(())
        .ok_or(AgentError::AuthorityRollback)
}

fn route(value: &str) -> bool {
    matches!(
        value,
        "source-options"
            | "source-approve"
            | "target-options"
            | "approval-options"
            | "target-approve"
            | "approve-revocation"
            | "cancel"
            | "revocation-finalize"
            | "independent-revocation-finalize"
    )
}
