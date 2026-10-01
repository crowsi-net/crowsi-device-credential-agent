use crate::{
    AgentError, config::AgentConfigDocument, config::RootTrustDocument, config::VerifiedConfig,
};

pub fn verify_config(
    config_wire: &[u8],
    root_wire: &[u8],
    now_epoch_s: u64,
) -> Result<VerifiedConfig, AgentError> {
    if config_wire.is_empty()
        || config_wire.len() > 262_144
        || root_wire.is_empty()
        || root_wire.len() > 16_384
    {
        return Err(AgentError::ConfigInvalid);
    }
    let config: AgentConfigDocument =
        serde_json::from_slice(config_wire).map_err(|_| AgentError::ConfigInvalid)?;
    let trust: RootTrustDocument =
        serde_json::from_slice(root_wire).map_err(|_| AgentError::ConfigInvalid)?;
    crate::config_validation::validate(&config, &trust, now_epoch_s)?;
    let value = serde_json::to_value(&config).map_err(|_| AgentError::ConfigInvalid)?;
    let payload =
        crate::crypto::canonical_signed_document("CROWSI-DEVICE-CREDENTIAL-CONFIG-V6", &value)?;
    if !crate::crypto::verify_hex(
        &trust.configuration_public_key_hex,
        &config.signature,
        &payload,
    ) {
        return Err(AgentError::ConfigInvalid);
    }
    Ok(VerifiedConfig(config))
}
