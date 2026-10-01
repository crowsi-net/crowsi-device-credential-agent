use crate::{AgentError, config::RemoteAuthorityRoute, crypto};

/// Computes the route identity from every deployment, peer, key, certificate, and timeout field.
///
/// # Errors
///
/// Returns an error when the closed route cannot be encoded.
pub fn authority_route_binding_sha256(route: &RemoteAuthorityRoute) -> Result<String, AgentError> {
    let mut value = serde_json::to_value(route).map_err(|_| AgentError::ConfigInvalid)?;
    value
        .as_object_mut()
        .ok_or(AgentError::ConfigInvalid)?
        .remove("binding_sha256");
    let payload = crypto::canonical_signed_document("CROWSI-AUTHORITY-ENDPOINT-ROUTE-V1", &value)?;
    Ok(crypto::digest(&payload))
}
