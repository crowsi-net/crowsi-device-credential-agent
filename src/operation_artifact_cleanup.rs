use crowsi_credential_authority_contracts::{
    ManagementOperationState, ManagementOperationV2, ManagementProjectionBodyV2,
    ManagementProjectionV2,
};

use crate::source_options_state_types::{
    FreshUvAttemptsV1, OperationJournalV1, PreparedOperationsV1,
};

pub(crate) fn terminal_projection(
    projection: &ManagementProjectionV2,
    prepared: &mut PreparedOperationsV1,
    fresh: &mut FreshUvAttemptsV1,
    journal: &mut OperationJournalV1,
    now: u64,
) -> Result<(), crate::AgentError> {
    match &projection.body {
        ManagementProjectionBodyV2::Operation { operation } => {
            cleanup(operation, prepared, fresh, journal, now)?;
        }
        ManagementProjectionBodyV2::Pending { operations } => {
            for operation in operations {
                cleanup(operation, prepared, fresh, journal, now)?;
            }
        }
        ManagementProjectionBodyV2::Snapshot { snapshot } => {
            for operation in &snapshot.pending_operations {
                cleanup(operation, prepared, fresh, journal, now)?;
            }
        }
    }
    Ok(())
}

fn cleanup(
    operation: &ManagementOperationV2,
    prepared: &mut PreparedOperationsV1,
    fresh: &mut FreshUvAttemptsV1,
    journal: &mut OperationJournalV1,
    now: u64,
) -> Result<(), crate::AgentError> {
    if matches!(
        operation.state,
        ManagementOperationState::Completed
            | ManagementOperationState::Rejected
            | ManagementOperationState::Cancelled
            | ManagementOperationState::Expired
    ) {
        crate::cancel_state_cleanup::operation(
            &operation.operation_id,
            prepared,
            fresh,
            journal,
            now,
        )?;
    }
    Ok(())
}
