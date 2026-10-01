use crowsi_credential_authority_contracts::{
    EndpointManagementEnvelopeV2, EndpointPreparedLookupRequestV1,
    EndpointPreparedLookupResponseV1, ManagementProjectionV2, ManagementRequestV2,
    SignedAuthorityExchangeV1,
};
use ihat_identity_assertion_contracts::AuthorityRequestV1;
use serde::{Deserialize, Serialize};

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ActorPreparedLookupV1 {
    pub operation_id: String,
    pub request: EndpointPreparedLookupRequestV1,
    pub response_json: String,
    pub response: EndpointPreparedLookupResponseV1,
    pub revocation_response_trust: Option<PreparedRevocationResponseTrustV1>,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PreparedRevocationResponseTrustV1 {
    pub key_id: String,
    pub public_key_hex: String,
    pub minimum_config_generation: u64,
}

#[derive(Clone, Copy, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum ActorOptionsPhaseV1 {
    CurrentPrepared,
    CurrentInvoking,
    CurrentUnknown,
    CurrentObservePrepared,
    CurrentObserveInvoking,
    CurrentObserveUnknown,
    LookupPrepared,
    BeginPrepared,
    CentralPrepared,
    CentralInvoking,
    Unknown,
    Complete,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ActorOptionsRecordV1 {
    pub operation_id: String,
    pub browser_request: ManagementRequestV2,
    pub browser_request_digest_sha256: String,
    pub phase: ActorOptionsPhaseV1,
    pub current_request: AuthorityRequestV1,
    pub current_exchange: Option<SignedAuthorityExchangeV1>,
    pub current_observed_at_epoch_s: Option<u64>,
    pub lookup_request: Option<EndpointPreparedLookupRequestV1>,
    pub central_envelope_json: Option<String>,
    pub central_envelope: Option<EndpointManagementEnvelopeV2>,
    pub response_json: Option<String>,
    pub response: Option<ManagementProjectionV2>,
    pub expires_at_epoch_s: u64,
    pub updated_at_epoch_s: u64,
}

pub(super) struct ActorOptionsResume {
    pub prepared: Option<Box<ActorPreparedLookupV1>>,
    pub fresh: Option<Box<crate::source_options_state_types::FreshUvAttemptV1>>,
    pub journal: Box<ActorOptionsRecordV1>,
}
