use crowsi_credential_authority_contracts::{
    ManagementProjectionBodyV2, ManagementProjectionV2, ManagementRequestV2,
    decode_endpoint_management_envelope_strict,
};

use crate::{
    AgentError, VerifiedConfig, replay::DurableSecurityState,
    retired_request_types::RetiredRequestReceiptV1, transport::AuthorityTransport,
};

#[allow(clippy::too_many_arguments)]
pub(super) fn invoke<T: AuthorityTransport>(
    config: &VerifiedConfig,
    state: &DurableSecurityState,
    transport: &T,
    browser: &ManagementRequestV2,
    value: &RetiredRequestReceiptV1,
    route: &str,
    envelope: &str,
    expected: Option<&ManagementProjectionBodyV2>,
    now: u64,
) -> Result<(Vec<u8>, ManagementProjectionV2), AgentError> {
    let decoded = decode_endpoint_management_envelope_strict(envelope.as_bytes())
        .map_err(|_| AgentError::AuthorityRollback)?;
    if value.route != route || decoded.browser_request != *browser {
        return Err(AgentError::AuthorityRollback);
    }
    let wire = transport.exchange(route, envelope.as_bytes(), now)?;
    let projection = if let Some(expected) = expected {
        crate::cancel_verify::retired_response(config, &decoded, expected, &wire, now)?
    } else {
        let projection =
            crate::core_projection::decode_and_verify(config, state, browser, &wire, now)?;
        crate::retired_request_refresh::exact_body(value, &projection)?;
        projection
    };
    Ok((wire, projection))
}
