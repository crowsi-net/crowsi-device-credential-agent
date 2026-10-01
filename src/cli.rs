use crowsi_credential_authority_contracts::decode_management_request_strict;
use std::{
    io::{Read, Write},
    path::Path,
};

use crate::{
    AgentError,
    config::verify_config,
    core::{AgentCore, command_route},
    identity_client::IdentityAuthorityClient,
    remote_transport::RemoteAuthorityTransport,
    validation,
};

const ROOT_TRUST_PATH: &str = "/etc/crowsi/device-credential-agent/root-trust.json";

pub fn run_cli(
    arguments: &[String],
    mut input: impl Read,
    mut output: impl Write,
) -> Result<(), AgentError> {
    if arguments.len() != 4 || arguments[2] != "--config" || !route(&arguments[1]) {
        return Err(AgentError::RequestInvalid);
    }
    let uid = crate::process_identity::effective_uid()?;
    let config_wire = validation::owner_file(Path::new(&arguments[3]), uid)?;
    let root_wire = root_trust()?;
    let now = now_epoch_s()?;
    let config = verify_config(&config_wire, &root_wire, now)?;
    crate::session_sender::validate(&config.0, uid)?;
    if arguments[1] == "initialize-once" {
        let mut unexpected = [0_u8; 1];
        if input
            .read(&mut unexpected)
            .map_err(|_| AgentError::RequestInvalid)?
            != 0
        {
            return Err(AgentError::RequestInvalid);
        }
        return crate::core::initialize_state(&config, uid);
    }
    let transport = RemoteAuthorityTransport::open(&config.0.authority_route, uid)?;
    let identity_transport =
        RemoteAuthorityTransport::open(&config.0.identity_authority_route, uid)?;
    let identity = IdentityAuthorityClient::open(&config.0, identity_transport, uid)?;
    let core = AgentCore::from_verified(config, transport, identity, uid)?;
    let mut request = Vec::new();
    input
        .by_ref()
        .take(262_145)
        .read_to_end(&mut request)
        .map_err(|_| AgentError::RequestInvalid)?;
    let decoded =
        decode_management_request_strict(&request).map_err(|_| AgentError::RequestInvalid)?;
    if request.len() > 262_144 || command_route(&decoded.command) != arguments[1] {
        return Err(AgentError::RequestInvalid);
    }
    output
        .write_all(&core.handle(&request, now)?)
        .map_err(|_| AgentError::ResponseInvalid)
}

fn route(value: &str) -> bool {
    matches!(
        value,
        "initialize-once"
            | "snapshot"
            | "source-options"
            | "source-approve"
            | "pending"
            | "target-options"
            | "target-approve"
            | "approval-options"
            | "approve-revocation"
            | "cancel"
            | "reconcile"
    )
}

fn root_trust() -> Result<Vec<u8>, AgentError> {
    validation::root_trust_file(Path::new(ROOT_TRUST_PATH))
}

fn now_epoch_s() -> Result<u64, AgentError> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|value| value.as_secs())
        .map_err(|_| AgentError::ConfigInvalid)
}
