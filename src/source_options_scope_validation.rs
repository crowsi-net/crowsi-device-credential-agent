use crowsi_credential_authority_contracts::{
    ManagementIntentV2 as I, ManagementOperationKind as K, ManagementOperationScopeV2 as S,
};

use crate::{AgentError, source_options_state_types::PreparedSourceOptionsV1};

pub(super) fn valid(value: &PreparedSourceOptionsV1) -> Result<(), AgentError> {
    let prepared = &value.prepared;
    let exact = match (
        &prepared.intent,
        &value.expected_operation_kind,
        &value.expected_operation_scope,
    ) {
        (
            I::DeviceTransfer {
                target_device_ref,
                credential_refs,
                ..
            },
            K::DeviceTransfer,
            S::DeviceTransfer {
                target_device_ref: target,
                credential_refs: credentials,
                ..
            },
        ) => target == target_device_ref && credentials == credential_refs,
        (
            I::DeviceRevocation {
                target_device_ref,
                expected_device_revocation_epoch,
                ..
            },
            K::DeviceRevocation,
            S::DeviceRevocation {
                target_device_ref: target,
                expected_device_revocation_epoch: epoch,
                revokes_session_refs,
                ..
            },
        ) => {
            target == target_device_ref
                && epoch == expected_device_revocation_epoch
                && prepared
                    .revocation
                    .as_ref()
                    .and_then(|item| item.expected_revoked_session_count)
                    == Some(revokes_session_refs.len() as u64)
        }
        (
            I::SessionRevocation {
                target_session_ref,
                expected_session_revocation_epoch,
                ..
            },
            K::SessionRevocation,
            S::SessionRevocation {
                target_session_ref: target,
                expected_session_revocation_epoch: epoch,
                device_ref,
            },
        ) => {
            target == target_session_ref
                && epoch == expected_session_revocation_epoch
                && prepared
                    .revocation
                    .as_ref()
                    .is_some_and(|item| item.target_device_ref == *device_ref)
        }
        _ => false,
    };
    exact.then_some(()).ok_or(AgentError::AuthorityRollback)
}
