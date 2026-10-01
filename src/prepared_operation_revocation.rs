use crowsi_credential_authority_contracts::{
    ManagementIntentV2, ManagementLifecycleV2, ManagementSnapshotV2, RevocationRequirementsV2,
};
use ihat_identity_assertion_contracts::IdentityEvidenceMetadata;

use crate::AgentError;

pub(super) fn build(
    snapshot: &ManagementSnapshotV2,
    intent: &ManagementIntentV2,
    identity: &IdentityEvidenceMetadata,
    finalization_authority: &str,
    approval_authority: &str,
) -> Result<Option<RevocationRequirementsV2>, AgentError> {
    let (target, count) = match intent {
        ManagementIntentV2::DeviceTransfer { .. } => return Ok(None),
        ManagementIntentV2::DeviceRevocation {
            target_device_ref, ..
        } => (
            target_device_ref.clone(),
            Some(active_session_count(snapshot, target_device_ref)?),
        ),
        ManagementIntentV2::SessionRevocation {
            target_session_ref,
            expected_session_revocation_epoch,
            ..
        } => (
            crate::prepared_operation_snapshot::session(
                snapshot,
                target_session_ref,
                *expected_session_revocation_epoch,
            )?
            .device_ref
            .clone(),
            None,
        ),
    };
    Ok(Some(RevocationRequirementsV2 {
        required_approval_authority_ref: (target != identity.assertion.device_id)
            .then(|| approval_authority.into()),
        target_device_ref: target,
        finalization_authority_id: finalization_authority.into(),
        expected_revoked_session_count: count,
    }))
}

fn active_session_count(snapshot: &ManagementSnapshotV2, device: &str) -> Result<u64, AgentError> {
    snapshot
        .sessions
        .iter()
        .filter(|value| value.device_ref == device && value.status == ManagementLifecycleV2::Active)
        .count()
        .try_into()
        .map_err(|_| AgentError::RequestInvalid)
}
