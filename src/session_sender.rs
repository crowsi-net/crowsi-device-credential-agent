use ed25519_dalek::{Signer, SigningKey};
use ihat_identity_assertion_contracts::{
    SIGNED_EVIDENCE_SCHEMA, SignedEvidenceV1, VerificationRole, canonical_signed_evidence,
};
use serde::Deserialize;
use std::path::Path;
use zeroize::Zeroizing;

use crate::{AgentError, config::AgentConfigDocument, crypto, validation};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SessionSenderKeyDocument {
    schema: String,
    key_id: String,
    private_key_hex: Zeroizing<String>,
}

pub(crate) fn validate(config: &AgentConfigDocument, uid: u32) -> Result<(), AgentError> {
    open(config, uid).map(|_| ())
}

pub(crate) struct SessionSender {
    key_id: String,
    fingerprint: String,
    signing: SigningKey,
}

impl SessionSender {
    pub(crate) fn sign(
        &self,
        proof_id: &str,
        binding_sha256: &str,
        now: u64,
    ) -> Result<SignedEvidenceV1, AgentError> {
        let mut value = SignedEvidenceV1 {
            schema: SIGNED_EVIDENCE_SCHEMA.into(),
            role: VerificationRole::SessionSender,
            proof_id: proof_id.into(),
            key_id: self.key_id.clone(),
            issued_at_epoch_s: now,
            expires_at_epoch_s: now.checked_add(15).ok_or(AgentError::ConfigInvalid)?,
            binding_sha256: binding_sha256.into(),
            signature: String::new(),
        };
        let wire = canonical_signed_evidence(&value).map_err(|_| AgentError::RequestInvalid)?;
        value.signature = hex::encode(self.signing.sign(&wire).to_bytes());
        Ok(value)
    }

    pub(crate) fn fingerprint(&self) -> &str {
        &self.fingerprint
    }
}

pub(crate) fn open(config: &AgentConfigDocument, uid: u32) -> Result<SessionSender, AgentError> {
    let wire = Zeroizing::new(validation::owner_file(
        Path::new(&config.session_sender_private_key_path),
        uid,
    )?);
    if crypto::digest(&wire) != config.session_sender_private_key_sha256 {
        return Err(AgentError::ConfigInvalid);
    }
    let document: SessionSenderKeyDocument =
        serde_json::from_slice(&wire).map_err(|_| AgentError::ConfigInvalid)?;
    let private = Zeroizing::new(
        hex::decode(document.private_key_hex.as_str()).map_err(|_| AgentError::ConfigInvalid)?,
    );
    let private: &[u8; 32] = private
        .as_slice()
        .try_into()
        .map_err(|_| AgentError::ConfigInvalid)?;
    let signing = SigningKey::from_bytes(private);
    let public = signing.verifying_key().to_bytes();
    let probe = b"CROWSI-SESSION-SENDER-KEY-SELF-CHECK-V1";
    let signature = signing.sign(probe);
    let valid = document.schema == "crowsi://device-credential-agent/session-sender-key/v1"
        && document.key_id == config.session_sender_key_id
        && hex::encode(public) == config.session_sender_public_key_hex
        && crypto::key_fingerprint(&public) == config.session_sender_key_fingerprint
        && signing
            .verifying_key()
            .verify_strict(probe, &signature)
            .is_ok();
    if !valid {
        return Err(AgentError::ConfigInvalid);
    }
    Ok(SessionSender {
        key_id: document.key_id,
        fingerprint: config.session_sender_key_fingerprint.clone(),
        signing,
    })
}
