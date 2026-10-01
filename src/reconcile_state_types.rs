use crowsi_credential_authority_contracts::{
    EndpointManagementEnvelopeV2, EndpointPreparedLookupRequestV1,
    EndpointPreparedLookupResponseV1, ManagementProjectionV2, ManagementRequestV2,
    SignedAuthorityExchangeV1,
};
use ihat_identity_assertion_contracts::AuthorityRequestV1;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum ReconcilePhaseV1 {
    CurrentPrepared,
    CurrentInvoking,
    CurrentUnknown,
    CurrentObservePrepared,
    CurrentObserveInvoking,
    CurrentObserveUnknown,
    LookupPrepared,
    LookupInvoking,
    LookupUnknown,
    CentralPrepared,
    CentralInvoking,
    Unknown,
    Complete,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ReconcileRecordV1 {
    pub operation_id: String,
    pub browser_request: ManagementRequestV2,
    pub browser_request_digest_sha256: String,
    pub phase: ReconcilePhaseV1,
    pub current_request: AuthorityRequestV1,
    pub current_exchange: Option<SignedAuthorityExchangeV1>,
    pub current_observed_at_epoch_s: Option<u64>,
    pub lookup_request: Option<EndpointPreparedLookupRequestV1>,
    pub lookup_response_json: Option<String>,
    pub lookup_response: Option<EndpointPreparedLookupResponseV1>,
    pub central_envelope_json: Option<String>,
    pub central_envelope: Option<EndpointManagementEnvelopeV2>,
    pub response_json: Option<String>,
    pub response: Option<ManagementProjectionV2>,
    pub expires_at_epoch_s: u64,
    pub retain_until_epoch_s: u64,
    pub updated_at_epoch_s: u64,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ReconcileRequestTombstoneV1 {
    pub browser_request_digest_sha256: String,
    pub operation_id: String,
    pub expired_at_epoch_s: u64,
    pub retain_until_epoch_s: u64,
}
