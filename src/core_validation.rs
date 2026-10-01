use crowsi_credential_authority_contracts::{
    ManagementCommandV2, ManagementIntentV2, ManagementRequestV2,
};

use crate::AgentError;

pub(super) fn validate_service(
    request: &ManagementRequestV2,
    configured: &str,
) -> Result<(), AgentError> {
    let supplied = match &request.command {
        ManagementCommandV2::Snapshot { service_id }
        | ManagementCommandV2::PendingList { service_id } => Some(service_id),
        ManagementCommandV2::SourceOptions { intent } => Some(match intent {
            ManagementIntentV2::DeviceTransfer { service_id, .. }
            | ManagementIntentV2::DeviceRevocation { service_id, .. }
            | ManagementIntentV2::SessionRevocation { service_id, .. } => service_id,
        }),
        _ => None,
    };
    if supplied.is_none_or(|value| value == configured) {
        Ok(())
    } else {
        Err(AgentError::RequestInvalid)
    }
}
