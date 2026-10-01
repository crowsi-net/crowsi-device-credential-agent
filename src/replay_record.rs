use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{AgentError, crypto};

pub(super) const BINDING_SCHEMA: &str = "crowsi://device-agent/durable-ledger-binding/v1";
pub(super) const STATE_SCHEMA: &str = "crowsi://device-agent/durable-ledger-state/v1";
pub(super) const ANCHOR_SCHEMA: &str = "crowsi://device-agent/durable-ledger-anchor/v1";
pub(super) const HEAD_SCHEMA: &str = "crowsi://device-agent/durable-ledger-head/v1";
pub(super) const SEAL_SCHEMA: &str = "crowsi://device-agent/durable-ledger-seal/v1";
pub(super) const COMMITTED_SCHEMA: &str = "crowsi://device-agent/durable-ledger-committed/v1";
pub(super) const TRANSACTION_SCHEMA: &str = "crowsi://device-agent/durable-ledger-transaction/v1";

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Binding {
    pub schema: String,
    pub ledger_id: String,
    pub endpoint_deployment_id: String,
    pub initial_configuration_generation: u64,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct StateRecord {
    pub schema: String,
    pub ledger_id: String,
    pub endpoint_deployment_id: String,
    pub configuration_generation: u64,
    pub revision: u64,
    pub previous_state_digest: Option<String>,
    pub payload_digest: String,
    pub payload: Value,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AnchorRecord {
    pub schema: String,
    pub ledger_id: String,
    pub endpoint_deployment_id: String,
    pub configuration_generation: u64,
    pub revision: u64,
    pub state_digest: String,
    pub previous_anchor_digest: Option<String>,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Head {
    pub schema: String,
    pub ledger_id: String,
    pub endpoint_deployment_id: String,
    pub configuration_generation: u64,
    pub revision: u64,
    pub state_digest: String,
    pub anchor_digest: String,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Seal {
    pub schema: String,
    pub binding_digest: String,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Committed {
    pub schema: String,
    pub binding_digest: String,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Transaction {
    pub schema: String,
    pub ledger_id: String,
    pub endpoint_deployment_id: String,
    pub configuration_generation: u64,
    pub base_revision: u64,
    pub base_state_digest: Option<String>,
    pub base_anchor_digest: Option<String>,
    pub state_name: String,
    pub anchor_name: String,
    pub head: Head,
}

pub(super) fn wire<T: Serialize>(value: &T) -> Result<Vec<u8>, AgentError> {
    serde_json::to_vec(value).map_err(|_| AgentError::AuthorityRollback)
}

pub(super) fn digest(wire: &[u8]) -> String {
    crypto::digest(wire)
}

pub(super) fn digest_hex(wire: &[u8]) -> String {
    digest(wire)
        .strip_prefix("sha256:")
        .unwrap_or_default()
        .to_owned()
}

pub(super) fn valid_digest(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
