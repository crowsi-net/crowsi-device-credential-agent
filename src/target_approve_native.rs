use crowsi_windows_operation_contracts::{OperationOnlyRequest, OperationOnlyResponse};

use crate::{
    AgentError, config::AgentConfigDocument, target_approve_state_types::TargetApproveResume,
};

pub(super) trait TargetApprovalPort {
    fn authorize(
        &self,
        config: &AgentConfigDocument,
        value: &TargetApproveResume,
        now: u64,
    ) -> Result<(Vec<u8>, OperationOnlyRequest), AgentError>;

    fn sign(
        &self,
        config: &AgentConfigDocument,
        value: &TargetApproveResume,
    ) -> Result<(Vec<u8>, OperationOnlyResponse), AgentError>;
}

pub(super) struct NativeTargetApprovalPort;

impl TargetApprovalPort for NativeTargetApprovalPort {
    fn authorize(
        &self,
        config: &AgentConfigDocument,
        value: &TargetApproveResume,
        now: u64,
    ) -> Result<(Vec<u8>, OperationOnlyRequest), AgentError> {
        crate::target_approve_pa::authorize(config, value, now)
    }

    fn sign(
        &self,
        config: &AgentConfigDocument,
        value: &TargetApproveResume,
    ) -> Result<(Vec<u8>, OperationOnlyResponse), AgentError> {
        crate::target_approve_custody::sign(config, value)
    }
}
