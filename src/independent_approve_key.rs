use ed25519_dalek::{Signer, SigningKey};
use ihat_identity_assertion_contracts::{
    SIGNED_EVIDENCE_SCHEMA, SignedEvidenceV1, VerificationRole, canonical_signed_evidence,
};
use serde::Deserialize;
use zeroize::Zeroizing;

use crate::{AgentError, config::AgentConfigDocument, crypto};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RecoveryApprovalKeyDocument {
    schema: String,
    key_id: String,
    private_key_hex: Zeroizing<String>,
}

pub(crate) struct RecoveryApprovalSigner {
    key_id: String,
    signing: SigningKey,
}

impl RecoveryApprovalSigner {
    pub(crate) fn sign(
        &self,
        proof_id: &str,
        binding: &str,
        now: u64,
    ) -> Result<SignedEvidenceV1, AgentError> {
        let mut value = SignedEvidenceV1 {
            schema: SIGNED_EVIDENCE_SCHEMA.into(),
            role: VerificationRole::RecoveryApproval,
            proof_id: proof_id.into(),
            key_id: self.key_id.clone(),
            issued_at_epoch_s: now,
            expires_at_epoch_s: now.checked_add(15).ok_or(AgentError::ConfigInvalid)?,
            binding_sha256: binding.into(),
            signature: String::new(),
        };
        let payload = canonical_signed_evidence(&value).map_err(|_| AgentError::RequestInvalid)?;
        value.signature = hex::encode(self.signing.sign(&payload).to_bytes());
        Ok(value)
    }
}

pub(crate) fn validate(config: &AgentConfigDocument, uid: u32) -> Result<(), AgentError> {
    open(config, uid).map(|_| ())
}

pub(crate) fn open(
    config: &AgentConfigDocument,
    uid: u32,
) -> Result<RecoveryApprovalSigner, AgentError> {
    let wire = Zeroizing::new(crate::independent_approve_key_io::read(
        &config.recovery_approval_private_key_path,
        uid,
    )?);
    if crypto::digest(&wire) != config.recovery_approval_private_key_sha256 {
        return Err(AgentError::ConfigInvalid);
    }
    let document: RecoveryApprovalKeyDocument =
        serde_json::from_slice(&wire).map_err(|_| AgentError::ConfigInvalid)?;
    let private = Zeroizing::new(
        hex::decode(document.private_key_hex.as_str()).map_err(|_| AgentError::ConfigInvalid)?,
    );
    let bytes: &[u8; 32] = private
        .as_slice()
        .try_into()
        .map_err(|_| AgentError::ConfigInvalid)?;
    let signing = SigningKey::from_bytes(bytes);
    let public = signing.verifying_key().to_bytes();
    let probe = b"CROWSI-RECOVERY-APPROVAL-KEY-SELF-CHECK-V1";
    let signature = signing.sign(probe);
    let valid = document.schema == "crowsi://device-credential-agent/recovery-approval-key/v1"
        && document.key_id == config.recovery_approval_key_id
        && hex::encode(public) == config.recovery_approval_public_key_hex
        && crypto::key_fingerprint(&public) == config.recovery_approval_key_fingerprint
        && signing
            .verifying_key()
            .verify_strict(probe, &signature)
            .is_ok();
    valid
        .then_some(RecoveryApprovalSigner {
            key_id: document.key_id,
            signing,
        })
        .ok_or(AgentError::ConfigInvalid)
}
