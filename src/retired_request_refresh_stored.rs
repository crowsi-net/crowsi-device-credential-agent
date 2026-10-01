use crowsi_credential_authority_contracts::{
    ManagementRequestV2, decode_endpoint_independent_revocation_finalize_request_strict,
    decode_endpoint_revocation_finalize_request_strict,
};

use crate::{
    AgentError, VerifiedConfig,
    replay::DurableSecurityState,
    retired_request_types::{RetiredRefreshMaterialV1, RetiredRequestReceiptV1},
};

pub(super) fn exists(
    config: &VerifiedConfig,
    state: &DurableSecurityState,
    browser: &ManagementRequestV2,
    value: &RetiredRequestReceiptV1,
    now: u64,
) -> Result<bool, AgentError> {
    let (Some(raw), Some(expected), Some(material)) = (
        value.response_json.as_deref(),
        value.response.as_ref(),
        value.refresh_material.as_ref(),
    ) else {
        return Ok(false);
    };
    let actual = match material {
        RetiredRefreshMaterialV1::ManagementEnvelope(_) => {
            crate::core_projection::decode_and_verify(config, state, browser, raw.as_bytes(), now)
        }
        RetiredRefreshMaterialV1::CancelEnvelope(_)
        | RetiredRefreshMaterialV1::CancelCleanupComplete(_) => {
            crate::core_projection::decode_and_verify(config, state, browser, raw.as_bytes(), now)
        }
        RetiredRefreshMaterialV1::RevocationFinalize(material) => {
            let request =
                decode_endpoint_revocation_finalize_request_strict(material.wire.as_bytes())
                    .map_err(|_| AgentError::AuthorityRollback)?;
            crate::source_approve_finalization_verify::request_response(
                config,
                &request,
                raw.as_bytes(),
                now,
            )
        }
        RetiredRefreshMaterialV1::IndependentRevocationFinalize(material) => {
            let request = decode_endpoint_independent_revocation_finalize_request_strict(
                material.wire.as_bytes(),
            )
            .map_err(|_| AgentError::AuthorityRollback)?;
            crate::independent_approve_finalize_flow::request_response(
                config,
                &request,
                raw.as_bytes(),
                now,
            )
        }
    };
    Ok(actual.is_ok_and(|actual| actual == *expected))
}
