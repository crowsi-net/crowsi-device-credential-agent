use crowsi_authority_transport::{AuthorityClient, ClientCredential};
use ed25519_dalek::SigningKey;
use serde::Deserialize;
use std::{path::Path, time::Duration};
use zeroize::Zeroizing;

use crate::{
    AgentError, config::RemoteAuthorityRoute, crypto, transport::AuthorityTransport, validation,
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RequestKeyDocument {
    schema: String,
    key_id: String,
    private_key_hex: Zeroizing<String>,
}

pub struct RemoteAuthorityTransport {
    binding: String,
    client: AuthorityClient,
}

impl RemoteAuthorityTransport {
    pub(crate) fn open(route: &RemoteAuthorityRoute, uid: u32) -> Result<Self, AgentError> {
        let certificate = pinned(
            &route.client_certificate_path,
            &route.client_certificate_sha256,
            uid,
        )?;
        let private_key = pinned(
            &route.client_private_key_path,
            &route.client_private_key_sha256,
            uid,
        )?;
        let trust = pinned(
            &route.server_trust_anchor_path,
            &route.server_trust_anchor_sha256,
            uid,
        )?;
        let request_wire = Zeroizing::new(pinned(
            &route.request_signing_key_path,
            &route.request_signing_key_sha256,
            uid,
        )?);
        let request: RequestKeyDocument =
            serde_json::from_slice(&request_wire).map_err(|_| AgentError::ConfigInvalid)?;
        let bytes = Zeroizing::new(
            hex::decode(request.private_key_hex.as_str()).map_err(|_| AgentError::ConfigInvalid)?,
        );
        let array: &[u8; 32] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| AgentError::ConfigInvalid)?;
        let signing = SigningKey::from_bytes(array);
        if request.schema != "crowsi://authority-transport/request-signing-key/v1"
            || request.key_id != route.request_key_id
            || hex::encode(signing.verifying_key().to_bytes()) != route.request_public_key_hex
        {
            return Err(AgentError::ConfigInvalid);
        }
        let client = AuthorityClient::new(
            &route.address,
            &route.server_name,
            &route.audience,
            &route.device_id,
            &route.response_key_id,
            &route.response_public_key_hex,
            ClientCredential {
                certificate_der: certificate,
                private_key_der: private_key.into(),
                server_trust_anchor_der: trust,
                expected_server_certificate_sha256: route.server_certificate_sha256.clone(),
                request_key_id: route.request_key_id.clone(),
                request_signing_key: signing,
            },
            Duration::from_millis(route.timeout_ms),
        )
        .map_err(|_| AgentError::ConfigInvalid)?;
        Ok(Self {
            binding: crate::config::authority_route_binding_sha256(route)?,
            client,
        })
    }
}

impl AuthorityTransport for RemoteAuthorityTransport {
    fn route_binding_sha256(&self) -> Result<String, AgentError> {
        Ok(self.binding.clone())
    }

    fn exchange(&self, command: &str, request: &[u8], now: u64) -> Result<Vec<u8>, AgentError> {
        let mut random = [0_u8; 32];
        getrandom::getrandom(&mut random).map_err(|_| AgentError::AuthorityUnavailable)?;
        self.client
            .exchange(command, request, &hex::encode(random), now)
            .map_err(|_| AgentError::AuthorityUnavailable)
    }
}

fn pinned(path: &str, digest: &str, uid: u32) -> Result<Vec<u8>, AgentError> {
    let bytes = validation::owner_file(Path::new(path), uid)?;
    if crypto::digest(&bytes) == digest {
        Ok(bytes)
    } else {
        Err(AgentError::ConfigInvalid)
    }
}
