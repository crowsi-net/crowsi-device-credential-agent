pub use crate::core::AgentCore;
pub use crate::identity_provider::IdentityEvidenceProvider;
pub use crate::transport::AuthorityTransport;

pub fn initialize_state(
    config_wire: &[u8],
    root_trust_wire: &[u8],
    now_epoch_s: u64,
    expected_uid: u32,
) -> Result<(), crate::AgentError> {
    let config = crate::config::verify_config(config_wire, root_trust_wire, now_epoch_s)?;
    crate::core::initialize_state(&config, expected_uid)
}

pub fn initialize_locator(
    config_wire: &[u8],
    root_trust_wire: &[u8],
    session_ref: &str,
    now_epoch_s: u64,
    expected_uid: u32,
) -> Result<(), crate::AgentError> {
    let config = crate::config::verify_config(config_wire, root_trust_wire, now_epoch_s)?;
    crate::core_test_support::initialize_locator(&config, session_ref, now_epoch_s, expected_uid)
}
