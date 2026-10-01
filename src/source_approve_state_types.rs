use crowsi_credential_authority_contracts::{
    EndpointManagementEnvelopeV2, EndpointRevocationExecutionReservationV1,
    EndpointRevocationExecutionReserveRequestV1, EndpointRevocationFinalizeRequestV1,
    ManagementProjectionV2, ManagementRequestV2, SignedAuthorityExchangeV1,
};
use ihat_identity_assertion_contracts::AuthorityRequestV1;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum SourceApprovePhaseV1 {
    FinishPrepared,
    CurrentPrepared,
    CurrentInvoking,
    CurrentUnknown,
    CurrentObservePrepared,
    CurrentObserveInvoking,
    CurrentObserveUnknown,
    RevocationBeginPrepared,
    ReservationCurrentPrepared,
    ReservationCurrentInvoking,
    ReservationCurrentUnknown,
    ReservationCurrentObservePrepared,
    ReservationCurrentObserveInvoking,
    ReservationCurrentObserveUnknown,
    ExecutionReservePrepared,
    ExecutionReserveInvoking,
    ExecutionReserveUnknown,
    RevocationFinalPrepared,
    RevocationFinalInvoking,
    RevocationFinalUnknown,
    CentralPrepared,
    CentralInvoking,
    Unknown,
    FinalizePrepared,
    FinalizeInvoking,
    FinalizeUnknown,
    Complete,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SourceApproveRecordV1 {
    pub operation_id: String,
    pub browser_request: ManagementRequestV2,
    pub browser_request_digest_sha256: String,
    pub phase: SourceApprovePhaseV1,
    pub finish_request: AuthorityRequestV1,
    pub finish_exchange: Option<SignedAuthorityExchangeV1>,
    pub current_request: Option<AuthorityRequestV1>,
    pub current_exchange: Option<SignedAuthorityExchangeV1>,
    pub current_observed_at_epoch_s: Option<u64>,
    pub revocation_begin_request: Option<AuthorityRequestV1>,
    pub revocation_begin_exchange: Option<SignedAuthorityExchangeV1>,
    pub revocation_response_key_id: Option<String>,
    pub revocation_response_public_key_hex: Option<String>,
    pub revocation_response_minimum_generation: Option<u64>,
    pub revocation_final_request: Option<AuthorityRequestV1>,
    pub revocation_final_exchange: Option<SignedAuthorityExchangeV1>,
    pub pre_final_response_json: Option<String>,
    pub pre_final_response: Option<ManagementProjectionV2>,
    pub revocation_finalize_request_id: Option<String>,
    pub reservation_current_request: Option<AuthorityRequestV1>,
    pub reservation_current_exchange: Option<SignedAuthorityExchangeV1>,
    pub reservation_current_observed_at_epoch_s: Option<u64>,
    pub execution_reserve_request_json: Option<String>,
    pub execution_reserve_request: Option<EndpointRevocationExecutionReserveRequestV1>,
    pub execution_reservation_json: Option<String>,
    pub execution_reservation: Option<EndpointRevocationExecutionReservationV1>,
    pub execution_reservation_trust: Option<SourceReservationTrustPinV1>,
    pub revocation_finalize_request_json: Option<String>,
    pub revocation_finalize_request: Option<EndpointRevocationFinalizeRequestV1>,
    pub central_envelope_json: Option<String>,
    pub central_envelope: Option<EndpointManagementEnvelopeV2>,
    pub response_json: Option<String>,
    pub response: Option<ManagementProjectionV2>,
    pub expires_at_epoch_s: u64,
    pub updated_at_epoch_s: u64,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SourceReservationTrustPinV1 {
    pub issuer: String,
    pub audience: String,
    pub key_id: String,
    pub public_key_hex: String,
    pub minimum_config_generation: u64,
    pub reservation_key_id: String,
    pub reservation_public_key_hex: String,
    pub minimum_reservation_config_generation: u64,
    pub minimum_snapshot_revision: u64,
    pub peer_device_ref: String,
    pub accepted_at_epoch_s: u64,
}

pub(super) struct SourceApproveResume {
    pub source: crate::source_options_state_types::PreparedSourceOptionsV1,
    pub selected_begin: SignedAuthorityExchangeV1,
    pub source_projection: ManagementProjectionV2,
    pub approval: Box<SourceApproveRecordV1>,
}
