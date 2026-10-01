use crowsi_credential_authority_contracts::{
    ENDPOINT_MANAGEMENT_ENVELOPE_SCHEMA, EndpointManagementEnvelopeV2,
    EndpointManagementEvidenceV2, ManagementCommandV2, ManagementRequestV2,
    SignedAuthorityExchangeV1,
};

use crate::AgentError;

pub(super) fn passive(
    browser_request: ManagementRequestV2,
    identity_exchange: SignedAuthorityExchangeV1,
) -> Result<EndpointManagementEnvelopeV2, AgentError> {
    if !matches!(
        browser_request.command,
        ManagementCommandV2::Snapshot { .. } | ManagementCommandV2::PendingList { .. }
    ) {
        return Err(AgentError::FreshUserVerificationRequired);
    }
    Ok(EndpointManagementEnvelopeV2 {
        schema: ENDPOINT_MANAGEMENT_ENVELOPE_SCHEMA.into(),
        browser_request,
        evidence: EndpointManagementEvidenceV2::Passive { identity_exchange },
    })
}
