use crowsi_credential_authority_contracts::{
    EndpointRevocationExecutionCancellationCleanupCompleteHistoricTrustV1,
    EndpointRevocationExecutionCancellationCleanupCompleteTrustV1,
};

use crate::cancel_state_types::{CancelCentralTrustPinV1, CancelResponseTrustPinV1};

pub(super) fn fresh<'a>(
    pin: &'a CancelCentralTrustPinV1,
    acknowledge: &'a CancelResponseTrustPinV1,
    now: u64,
) -> EndpointRevocationExecutionCancellationCleanupCompleteTrustV1<'a> {
    EndpointRevocationExecutionCancellationCleanupCompleteTrustV1 {
        issuer: &pin.issuer,
        audience: &pin.audience,
        key_id: &pin.key_id,
        public_key_hex: &pin.public_key_hex,
        minimum_config_generation: pin.minimum_config_generation,
        cleanup_key_id: &pin.root_key_id,
        cleanup_public_key_hex: &pin.root_public_key_hex,
        minimum_cleanup_config_generation: pin.minimum_root_config_generation,
        acknowledge_key_id: &acknowledge.key_id,
        acknowledge_public_key_hex: &acknowledge.public_key_hex,
        minimum_acknowledge_config_generation: acknowledge.minimum_config_generation,
        minimum_snapshot_revision: pin.minimum_snapshot_revision,
        now_epoch_s: now,
    }
}

pub(super) fn historic<'a>(
    pin: &'a CancelCentralTrustPinV1,
    acknowledge: &'a CancelResponseTrustPinV1,
) -> EndpointRevocationExecutionCancellationCleanupCompleteHistoricTrustV1<'a> {
    EndpointRevocationExecutionCancellationCleanupCompleteHistoricTrustV1 {
        issuer: &pin.issuer,
        audience: &pin.audience,
        key_id: &pin.key_id,
        public_key_hex: &pin.public_key_hex,
        minimum_config_generation: pin.minimum_config_generation,
        cleanup_key_id: &pin.root_key_id,
        cleanup_public_key_hex: &pin.root_public_key_hex,
        minimum_cleanup_config_generation: pin.minimum_root_config_generation,
        acknowledge_key_id: &acknowledge.key_id,
        acknowledge_public_key_hex: &acknowledge.public_key_hex,
        minimum_acknowledge_config_generation: acknowledge.minimum_config_generation,
        minimum_snapshot_revision: pin.minimum_snapshot_revision,
        accepted_at_epoch_s: pin.accepted_at_epoch_s,
    }
}
