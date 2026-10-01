use crate::{
    AgentError, VerifiedConfig,
    replay::DurableSecurityState,
    retired_request_types::{RetiredRefreshMaterialV1, RetiredRequestReceiptV1},
    transport::AuthorityTransport,
};
use crowsi_credential_authority_contracts::{
    ManagementProjectionV2, ManagementRequestV2, decode_endpoint_revocation_finalize_request_strict,
};
pub(crate) fn response<T: AuthorityTransport>(
    config: &VerifiedConfig,
    state: &DurableSecurityState,
    transport: &T,
    browser: &ManagementRequestV2,
    value: RetiredRequestReceiptV1,
    now: u64,
) -> Result<Vec<u8>, AgentError> {
    if crate::retired_request_refresh_stored::exists(config, state, browser, &value, now)? {
        return Ok(value
            .response_json
            .as_deref()
            .ok_or(AgentError::AuthorityRollback)?
            .as_bytes()
            .to_vec());
    }
    if now >= value.refresh_until_epoch_s {
        return Err(AgentError::OperationReplay);
    }
    let material = value
        .refresh_material
        .as_ref()
        .ok_or(AgentError::OperationReplay)?;
    let (wire, projection) = match material {
        RetiredRefreshMaterialV1::ManagementEnvelope(material) => {
            crate::retired_request_refresh_management::invoke(
                config,
                state,
                transport,
                browser,
                &value,
                &material.route,
                &material.wire,
                None,
                now,
            )?
        }
        RetiredRefreshMaterialV1::CancelEnvelope(material) => {
            crate::retired_request_refresh_management::invoke(
                config,
                state,
                transport,
                browser,
                &value,
                "cancel",
                &material.wire,
                Some(&material.expected_body),
                now,
            )?
        }
        RetiredRefreshMaterialV1::CancelCleanupComplete(material) => {
            if now < material.delivery.token.issued_at_epoch_s {
                return Err(AgentError::AuthorityRollback);
            }
            crate::retired_request_refresh_management::invoke(
                config,
                state,
                transport,
                browser,
                &value,
                "cancel",
                &material.wire,
                Some(&material.expected_body),
                now,
            )?
        }
        RetiredRefreshMaterialV1::RevocationFinalize(material) => {
            finalize(config, transport, browser, &value, &material.wire, now)?
        }
        RetiredRefreshMaterialV1::IndependentRevocationFinalize(material) => {
            crate::retired_request_refresh_independent::invoke(
                config,
                transport,
                browser,
                &value,
                &material.wire,
                now,
            )?
        }
    };
    crate::retired_request_refresh_store::store(
        config,
        state,
        browser,
        &value,
        &wire,
        &projection,
        now,
    )?;
    Ok(wire)
}

fn finalize<T: AuthorityTransport>(
    config: &VerifiedConfig,
    transport: &T,
    browser: &ManagementRequestV2,
    value: &RetiredRequestReceiptV1,
    request_wire: &str,
    now: u64,
) -> Result<(Vec<u8>, ManagementProjectionV2), AgentError> {
    let request = decode_endpoint_revocation_finalize_request_strict(request_wire.as_bytes())
        .map_err(|_| AgentError::AuthorityRollback)?;
    if value.route != "revocation-finalize"
        || request.source_approve_request != *browser
        || request.operation_id != value.operation_id
    {
        return Err(AgentError::AuthorityRollback);
    }
    let wire = transport.exchange("revocation-finalize", request_wire.as_bytes(), now)?;
    let projection =
        crate::source_approve_finalization_verify::request_response(config, &request, &wire, now)?;
    compatible_body(value, &projection)?;
    Ok((wire, projection))
}

pub(super) fn exact_body(
    value: &RetiredRequestReceiptV1,
    projection: &ManagementProjectionV2,
) -> Result<(), AgentError> {
    value
        .response
        .as_ref()
        .is_some_and(|expected| expected.body == projection.body)
        .then_some(())
        .ok_or(AgentError::AuthorityResponseInvalid)
}

fn compatible_body(
    value: &RetiredRequestReceiptV1,
    projection: &ManagementProjectionV2,
) -> Result<(), AgentError> {
    value
        .response
        .as_ref()
        .is_some_and(|expected| {
            crate::retired_request_refresh_independent::compatible(&expected.body, &projection.body)
        })
        .then_some(())
        .ok_or(AgentError::AuthorityResponseInvalid)
}
