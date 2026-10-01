use crowsi_credential_authority_contracts::{
    EndpointIndependentRevocationFinalizeRequestV1, EndpointIndependentRevocationPreFinalRequestV1,
    EndpointRevocationExecutionReservationV1, EndpointRevocationExecutionReserveRequestV1,
    ManagementProjectionV2, ManagementRequestV2, SignedAuthorityExchangeV1,
};
use ihat_identity_assertion_contracts::AuthorityRequestV1;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum IndependentApprovePhaseV1 {
    FinishPrepared,
    FinishInvoking,
    FinishUnknown,
    CurrentRequestPrepared,
    CurrentPrepared,
    CurrentInvoking,
    CurrentUnknown,
    CurrentObservePrepared,
    CurrentObserveInvoking,
    CurrentObserveUnknown,
    ApprovalPrepared,
    ApprovalInvoking,
    ApprovalUnknown,
    ApprovalAccepted,
    PreFinalPrepared,
    PreFinalInvoking,
    PreFinalUnknown,
    PreFinalAccepted,
    ReservationCurrentPrepared,
    ReservationCurrentInvoking,
    ReservationCurrentUnknown,
    ReservationCurrentObservePrepared,
    ReservationCurrentObserveInvoking,
    ReservationCurrentObserveUnknown,
    ExecutionReservePrepared,
    ExecutionReserveInvoking,
    ExecutionReserveUnknown,
    FinalPrepared,
    FinalInvoking,
    FinalUnknown,
    FinalAccepted,
    FinalizePrepared,
    FinalizeInvoking,
    FinalizeUnknown,
    Complete,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct IndependentProjectionTrustPinV1 {
    pub issuer: String,
    pub audience: String,
    pub key_id: String,
    pub public_key_hex: String,
    pub minimum_snapshot_revision: u64,
    pub peer_device_ref: String,
    pub accepted_at_epoch_s: u64,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct IndependentReservationTrustPinV1 {
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

include!("independent_approve_state_record.rs");
