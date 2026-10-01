use crowsi_credential_authority_contracts::{EndpointPreparedOperationV2, ManagementIntentV2};
use ihat_identity_assertion_contracts::{
    AuthorityCommand, BeginDeviceRevocationCommand, BeginSessionRevocationCommand,
    FreshAuthenticationDto, FreshUvV1,
};

pub(crate) fn matches(
    prepared: &EndpointPreparedOperationV2,
    fresh: &FreshUvV1,
    command: &AuthorityCommand,
    command_id: &str,
) -> bool {
    let authentication = crate::source_approve_revocation_request::authentication(fresh);
    match (&prepared.intent, command) {
        (
            ManagementIntentV2::DeviceRevocation {
                service_id,
                target_device_ref,
                expected_device_revocation_epoch,
                ..
            },
            AuthorityCommand::BeginDeviceRevocation(value),
        ) => {
            common(
                prepared,
                fresh,
                value,
                command_id,
                service_id,
                &authentication,
            ) && value.target_device_id == *target_device_ref
                && value.expected_device_epoch == *expected_device_revocation_epoch
        }
        (
            ManagementIntentV2::SessionRevocation {
                service_id,
                target_session_ref,
                expected_session_revocation_epoch,
                ..
            },
            AuthorityCommand::BeginSessionRevocation(value),
        ) => {
            common(
                prepared,
                fresh,
                value,
                command_id,
                service_id,
                &authentication,
            ) && value.target_session_ref == *target_session_ref
                && value.expected_session_epoch == *expected_session_revocation_epoch
        }
        _ => false,
    }
}

trait CommonCommand {
    fn common(&self) -> Common<'_>;
}

struct Common<'a> {
    command_id: &'a str,
    finalize_id: &'a str,
    service: &'a str,
    pairwise: &'a str,
    device: &'a str,
    session: &'a str,
    nonce: &'a str,
    authentication: &'a FreshAuthenticationDto,
}

macro_rules! common_command {
    ($command:ty) => {
        impl CommonCommand for $command {
            fn common(&self) -> Common<'_> {
                Common {
                    command_id: &self.command_id,
                    finalize_id: &self.finalize_command_id,
                    service: &self.service_id,
                    pairwise: &self.pairwise_subject,
                    device: &self.source_device_id,
                    session: &self.source_session_ref,
                    nonce: &self.identity_nonce,
                    authentication: &self.authentication,
                }
            }
        }
    };
}

common_command!(BeginDeviceRevocationCommand);
common_command!(BeginSessionRevocationCommand);

fn common<C: CommonCommand>(
    prepared: &EndpointPreparedOperationV2,
    fresh: &FreshUvV1,
    value: &C,
    command_id: &str,
    service: &str,
    authentication: &FreshAuthenticationDto,
) -> bool {
    let observed = value.common();
    observed.command_id == command_id
        && observed.finalize_id == prepared.operation_id
        && observed.service == service
        && service == fresh.service_id
        && observed.pairwise == prepared.pairwise_subject
        && observed.device == prepared.source_device_ref
        && observed.session == prepared.source_session_ref
        && observed.nonce == fresh.identity_nonce
        && observed.nonce == prepared.source_identity_nonce
        && observed.authentication == authentication
}
