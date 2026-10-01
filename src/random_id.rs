use crate::AgentError;

pub(crate) fn create(prefix: &str) -> Result<String, AgentError> {
    let mut bytes = [0_u8; 32];
    getrandom::getrandom(&mut bytes).map_err(|_| AgentError::IdentityUnavailable)?;
    Ok(format!("{prefix}_{}", hex::encode(bytes)))
}
