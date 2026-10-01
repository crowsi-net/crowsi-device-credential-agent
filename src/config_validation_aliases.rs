use std::{collections::BTreeSet, path::Path};

use crate::config::{AgentConfigDocument, RemoteAuthorityRoute};

pub(crate) fn distinct(value: &AgentConfigDocument) -> bool {
    let Some(device_key) = value.device_proof_keys.first() else {
        return false;
    };
    let routes = [&value.authority_route, &value.identity_authority_route];
    let mut paths = Vec::new();
    let mut digests = Vec::new();
    for route in routes {
        route_inputs(route, &mut paths, &mut digests);
    }
    paths.extend([
        value.session_sender_private_key_path.as_str(),
        value.recovery_approval_private_key_path.as_str(),
        value.pa_authorization_route.executable.as_str(),
        value.pa_authorization_route.config_path.as_str(),
        device_key.custody_executable.as_str(),
    ]);
    digests.extend([
        value.session_sender_private_key_sha256.as_str(),
        value.recovery_approval_private_key_sha256.as_str(),
        value.pa_authorization_route.executable_sha256.as_str(),
        value.pa_authorization_route.config_sha256.as_str(),
        device_key.custody_executable_sha256.as_str(),
    ]);
    all_unique(&paths)
        && all_unique(&digests)
        && paths.iter().all(|path| outside_state(value, path))
}

fn route_inputs<'a>(
    route: &'a RemoteAuthorityRoute,
    paths: &mut Vec<&'a str>,
    digests: &mut Vec<&'a str>,
) {
    paths.extend([
        route.client_certificate_path.as_str(),
        route.client_private_key_path.as_str(),
        route.server_trust_anchor_path.as_str(),
        route.request_signing_key_path.as_str(),
    ]);
    digests.extend([
        route.client_certificate_sha256.as_str(),
        route.client_private_key_sha256.as_str(),
        route.server_trust_anchor_sha256.as_str(),
        route.server_certificate_sha256.as_str(),
        route.request_signing_key_sha256.as_str(),
    ]);
}

fn all_unique(values: &[&str]) -> bool {
    values.iter().copied().collect::<BTreeSet<_>>().len() == values.len()
}

fn outside_state(value: &AgentConfigDocument, path: &str) -> bool {
    let path = Path::new(path);
    !path.starts_with(&value.endpoint_state_directory)
        && !path.starts_with(&value.endpoint_anchor_directory)
}
