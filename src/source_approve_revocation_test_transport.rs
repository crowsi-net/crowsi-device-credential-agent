use std::sync::Mutex;

use crowsi_credential_authority_contracts::EndpointAuthorityResponseTrustV2;
use ed25519_dalek::{Signer, SigningKey};
use ihat_identity_assertion_contracts::{
    AUTHORITY_RESPONSE_SCHEMA, AuthorityCommand, AuthorityResponseV1, AuthorityResult,
    DeviceRevocationMetadata, ResponseOutcome, RevocationCeremonyMetadata,
    RevocationCeremonyStateDto, RevocationMetadata, canonical_response, command_digest,
    decode_authority_request_strict,
};

use crate::{AgentError, transport::AuthorityTransport};

use super::source_approve_revocation_test_values::{NOW, TARGET_DIGEST};

pub(super) struct FixtureTransport {
    signing: SigningKey,
    public_key_hex: String,
    independent: bool,
    generation: u64,
    requests: Mutex<Vec<Vec<u8>>>,
}

impl FixtureTransport {
    pub(super) fn new(independent: bool) -> Self {
        Self::with_generation(independent, 7)
    }

    pub(super) fn with_generation(independent: bool, generation: u64) -> Self {
        let signing = SigningKey::from_bytes(&[7; 32]);
        let public_key_hex = hex::encode(signing.verifying_key().to_bytes());
        Self {
            signing,
            public_key_hex,
            independent,
            generation,
            requests: Mutex::new(Vec::new()),
        }
    }

    pub(super) fn trust(&self) -> EndpointAuthorityResponseTrustV2<'_> {
        EndpointAuthorityResponseTrustV2 {
            minimum_config_generation: 7,
            key_id: "authority-response-key",
            public_key_hex: &self.public_key_hex,
        }
    }

    pub(super) fn requests(&self) -> Vec<Vec<u8>> {
        self.requests.lock().expect("request lock").clone()
    }

    fn result(&self, command: &AuthorityCommand) -> Result<AuthorityResult, AgentError> {
        let result = match command {
            AuthorityCommand::BeginDeviceRevocation(value) => {
                self.begun(value.finalize_command_id.clone())
            }
            AuthorityCommand::BeginSessionRevocation(value) => {
                self.begun(value.finalize_command_id.clone())
            }
            AuthorityCommand::RevokeDeviceByRef(value) => {
                AuthorityResult::DeviceRevocation(DeviceRevocationMetadata {
                    target_digest: TARGET_DIGEST.into(),
                    previous_device_epoch: value.expected_device_epoch,
                    current_device_epoch: value.expected_device_epoch + 1,
                    revoked_session_count: 2,
                    audit_sequence: 9,
                })
            }
            AuthorityCommand::RevokeSessionByRef(value) => {
                AuthorityResult::Revocation(RevocationMetadata {
                    target_digest: TARGET_DIGEST.into(),
                    previous_epoch: value.expected_epoch,
                    current_epoch: value.expected_epoch + 1,
                    audit_sequence: 10,
                })
            }
            _ => return Err(AgentError::RequestInvalid),
        };
        Ok(result)
    }

    fn begun(&self, finalize_command_id: String) -> AuthorityResult {
        AuthorityResult::RevocationBegun(RevocationCeremonyMetadata {
            attempt_id: "revocation-attempt".into(),
            finalize_command_id,
            target_digest: TARGET_DIGEST.into(),
            expires_at_epoch_s: NOW + 300,
            independent_approval_required: self.independent,
            state: if self.independent {
                RevocationCeremonyStateDto::AwaitingIndependentApproval
            } else {
                RevocationCeremonyStateDto::ReadyToFinalize
            },
            approval_nonce: self.independent.then(|| "approval-nonce".into()),
        })
    }
}

impl AuthorityTransport for FixtureTransport {
    fn route_binding_sha256(&self) -> Result<String, AgentError> {
        Ok("66".repeat(32))
    }

    fn exchange(&self, route: &str, wire: &[u8], _now: u64) -> Result<Vec<u8>, AgentError> {
        if route != "ihat_authority_v1" {
            return Err(AgentError::RequestInvalid);
        }
        let request =
            decode_authority_request_strict(wire).map_err(|_| AgentError::RequestInvalid)?;
        self.requests
            .lock()
            .map_err(|_| AgentError::AuthorityUnavailable)?
            .push(wire.to_vec());
        let mut response = AuthorityResponseV1 {
            schema: AUTHORITY_RESPONSE_SCHEMA.into(),
            request_id: request.request_id.clone(),
            command_type: request.command.type_name().into(),
            command_digest: command_digest(&request).map_err(|_| AgentError::RequestInvalid)?,
            config_generation: self.generation,
            issued_at_epoch_s: NOW,
            expires_at_epoch_s: NOW + 30,
            outcome: ResponseOutcome::Committed {
                result: self.result(&request.command)?,
            },
            key_id: "authority-response-key".into(),
            signature: String::new(),
        };
        let canonical =
            canonical_response(&response).map_err(|_| AgentError::AuthorityResponseInvalid)?;
        response.signature = hex::encode(self.signing.sign(&canonical).to_bytes());
        serde_json::to_vec(&response).map_err(|_| AgentError::AuthorityResponseInvalid)
    }
}
