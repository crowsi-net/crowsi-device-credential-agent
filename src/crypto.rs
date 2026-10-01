use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::AgentError;

pub fn canonical_signed_document(domain: &str, value: &Value) -> Result<Vec<u8>, AgentError> {
    let mut unsigned = value.clone();
    unsigned
        .as_object_mut()
        .ok_or(AgentError::ConfigInvalid)?
        .remove("signature");
    let body = serde_json::to_vec(&unsigned).map_err(|_| AgentError::ConfigInvalid)?;
    let mut output = domain.as_bytes().to_vec();
    output.push(b'\n');
    output.extend_from_slice(body.len().to_string().as_bytes());
    output.push(b'\n');
    output.extend_from_slice(&body);
    Ok(output)
}

pub(crate) fn verify_hex(public_key_hex: &str, signature_hex: &str, message: &[u8]) -> bool {
    let Ok(public): Result<[u8; 32], _> = hex::decode(public_key_hex).and_then(|value| {
        value
            .try_into()
            .map_err(|_| hex::FromHexError::InvalidStringLength)
    }) else {
        return false;
    };
    let Ok(signature_bytes) = hex::decode(signature_hex) else {
        return false;
    };
    let Ok(key) = VerifyingKey::from_bytes(&public) else {
        return false;
    };
    let Ok(signature) = Signature::try_from(signature_bytes.as_slice()) else {
        return false;
    };
    key.verify(message, &signature).is_ok()
}

pub(crate) fn digest(bytes: &[u8]) -> String {
    format!("sha256:{}", key_fingerprint(bytes))
}

pub(crate) fn key_fingerprint(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
