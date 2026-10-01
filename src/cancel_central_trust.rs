use crowsi_credential_authority_contracts::{
    EndpointRevocationExecutionCancellationCleanupHistoricTrustV1,
    EndpointRevocationExecutionCancellationCleanupTrustV1,
    EndpointRevocationExecutionCancellationHistoricTrustV1,
    EndpointRevocationExecutionCancellationTrustV1,
};

use crate::{VerifiedConfig, cancel_state_types::CancelCentralTrustPinV1};

pub(super) fn pin(config: &VerifiedConfig, now: u64) -> CancelCentralTrustPinV1 {
    let trust = &config.0.management_projection_trust;
    CancelCentralTrustPinV1 {
        issuer: trust.issuer.clone(),
        audience: trust.audience.clone(),
        key_id: trust.key_id.clone(),
        public_key_hex: trust.public_key_hex.clone(),
        minimum_config_generation: config.0.minimum_reservation_config_generation,
        root_key_id: config.0.revocation_execution_reservation_key_id.clone(),
        root_public_key_hex: config
            .0
            .revocation_execution_reservation_public_key_hex
            .clone(),
        minimum_root_config_generation: config.0.minimum_reservation_config_generation,
        minimum_snapshot_revision: trust.minimum_snapshot_revision,
        peer_device_ref: config.0.authority_route.device_id.clone(),
        accepted_at_epoch_s: now,
    }
}

pub(super) fn cancellation_fresh(
    pin: &CancelCentralTrustPinV1,
    now: u64,
) -> EndpointRevocationExecutionCancellationTrustV1<'_> {
    EndpointRevocationExecutionCancellationTrustV1 {
        issuer: &pin.issuer,
        audience: &pin.audience,
        key_id: &pin.key_id,
        public_key_hex: &pin.public_key_hex,
        minimum_config_generation: pin.minimum_config_generation,
        cancellation_key_id: &pin.root_key_id,
        cancellation_public_key_hex: &pin.root_public_key_hex,
        minimum_cancellation_config_generation: pin.minimum_root_config_generation,
        minimum_snapshot_revision: pin.minimum_snapshot_revision,
        now_epoch_s: now,
    }
}

pub(super) fn cancellation_historic(
    pin: &CancelCentralTrustPinV1,
) -> EndpointRevocationExecutionCancellationHistoricTrustV1<'_> {
    EndpointRevocationExecutionCancellationHistoricTrustV1 {
        issuer: &pin.issuer,
        audience: &pin.audience,
        key_id: &pin.key_id,
        public_key_hex: &pin.public_key_hex,
        minimum_config_generation: pin.minimum_config_generation,
        cancellation_key_id: &pin.root_key_id,
        cancellation_public_key_hex: &pin.root_public_key_hex,
        minimum_cancellation_config_generation: pin.minimum_root_config_generation,
        minimum_snapshot_revision: pin.minimum_snapshot_revision,
        accepted_at_epoch_s: pin.accepted_at_epoch_s,
    }
}

pub(super) fn cleanup_fresh(
    pin: &CancelCentralTrustPinV1,
    now: u64,
) -> EndpointRevocationExecutionCancellationCleanupTrustV1<'_> {
    EndpointRevocationExecutionCancellationCleanupTrustV1 {
        issuer: &pin.issuer,
        audience: &pin.audience,
        key_id: &pin.key_id,
        public_key_hex: &pin.public_key_hex,
        minimum_config_generation: pin.minimum_config_generation,
        cleanup_key_id: &pin.root_key_id,
        cleanup_public_key_hex: &pin.root_public_key_hex,
        minimum_cleanup_config_generation: pin.minimum_root_config_generation,
        minimum_snapshot_revision: pin.minimum_snapshot_revision,
        now_epoch_s: now,
    }
}

pub(super) fn cleanup_historic(
    pin: &CancelCentralTrustPinV1,
) -> EndpointRevocationExecutionCancellationCleanupHistoricTrustV1<'_> {
    EndpointRevocationExecutionCancellationCleanupHistoricTrustV1 {
        issuer: &pin.issuer,
        audience: &pin.audience,
        key_id: &pin.key_id,
        public_key_hex: &pin.public_key_hex,
        minimum_config_generation: pin.minimum_config_generation,
        cleanup_key_id: &pin.root_key_id,
        cleanup_public_key_hex: &pin.root_public_key_hex,
        minimum_cleanup_config_generation: pin.minimum_root_config_generation,
        minimum_snapshot_revision: pin.minimum_snapshot_revision,
        accepted_at_epoch_s: pin.accepted_at_epoch_s,
    }
}
