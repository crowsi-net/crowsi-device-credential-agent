use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum CancelPhaseV1 {
    CurrentPrepared,
    CurrentInvoking,
    CurrentUnknown,
    CurrentObservePrepared,
    CurrentObserveInvoking,
    CurrentObserveUnknown,
    LookupPrepared,
    CentralPrepared,
    CentralInvoking,
    Unknown,
    ExecutionCancelPrepared,
    ExecutionCancelInvoking,
    ExecutionCancelUnknown,
    CancelPendingPrepared,
    CancelPendingInvoking,
    CancelPendingUnknown,
    CancelFinalizePrepared,
    CancelFinalizeInvoking,
    CancelFinalizeUnknown,
    CleanupAckPrepared,
    CleanupAckInvoking,
    CleanupAckUnknown,
    CleanupCompletePrepared,
    CleanupCompleteInvoking,
    CleanupCompleteUnknown,
    CleanupCompleteCleanupPrepared,
    CleanupCompleteCleanupInvoking,
    CleanupCompleteCleanupUnknown,
    CleanupCompleteAckPrepared,
    CleanupCompleteAckInvoking,
    CleanupCompleteAckUnknown,
    CleanupCompleteAccepted,
    Complete,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CancelCentralTrustPinV1 {
    pub issuer: String,
    pub audience: String,
    pub key_id: String,
    pub public_key_hex: String,
    pub minimum_config_generation: u64,
    pub root_key_id: String,
    pub root_public_key_hex: String,
    pub minimum_root_config_generation: u64,
    pub minimum_snapshot_revision: u64,
    pub peer_device_ref: String,
    pub accepted_at_epoch_s: u64,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CancelResponseTrustPinV1 {
    pub key_id: String,
    pub public_key_hex: String,
    pub minimum_config_generation: u64,
}

include!("cancel_state_record.rs");

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CancelRequestTombstoneV1 {
    pub browser_request_digest_sha256: String,
    pub operation_id: String,
    pub expired_at_epoch_s: u64,
    pub retain_until_epoch_s: u64,
}
