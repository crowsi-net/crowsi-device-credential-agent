use serde_json::Value;
use std::collections::BTreeMap;

use crate::AgentError;

const MAXIMUM_DOCUMENT_BYTES: usize = 450_000;

pub(super) fn validate(records: &BTreeMap<String, Value>) -> Result<(), AgentError> {
    let wire = serde_json::to_vec(records).map_err(|_| AgentError::AuthorityRollback)?;
    if wire.len() > MAXIMUM_DOCUMENT_BYTES {
        return Err(AgentError::AuthorityRollback);
    }
    for (name, value) in records {
        let policy = policy(name).ok_or(AgentError::AuthorityRollback)?;
        let size = serde_json::to_vec(value)
            .map_err(|_| AgentError::AuthorityRollback)?
            .len();
        if value.is_null() || size > policy.bytes {
            return Err(AgentError::AuthorityRollback);
        }
        let mut nodes = 0;
        walk(value, policy, 0, &mut nodes)?;
    }
    Ok(())
}

#[derive(Clone, Copy)]
struct Policy {
    bytes: usize,
    items: usize,
    nodes: usize,
    depth: usize,
}

fn policy(name: &str) -> Option<Policy> {
    let value = match name {
        "management-projection" => Policy {
            bytes: 280_000,
            items: 1_024,
            nodes: 8_192,
            depth: 12,
        },
        "identity-session-locator" => Policy {
            bytes: 16_384,
            items: 64,
            nodes: 128,
            depth: 12,
        },
        "device-enrollment" => Policy {
            bytes: 32_768,
            items: 64,
            nodes: 256,
            depth: 12,
        },
        "prepared-operation" => Policy {
            bytes: 65_536,
            items: 128,
            nodes: 512,
            depth: 12,
        },
        "fresh-uv-attempt" => Policy {
            bytes: 32_768,
            items: 64,
            nodes: 256,
            depth: 12,
        },
        "operation-journal" => Policy {
            bytes: 131_072,
            items: 256,
            nodes: 2_048,
            depth: 32,
        },
        "transport-replay" => Policy {
            bytes: 131_072,
            items: 256,
            nodes: 2_048,
            depth: 12,
        },
        _ => return None,
    };
    Some(value)
}

fn walk(value: &Value, policy: Policy, depth: usize, nodes: &mut usize) -> Result<(), AgentError> {
    *nodes = nodes.checked_add(1).ok_or(AgentError::AuthorityRollback)?;
    if depth > policy.depth || *nodes > policy.nodes {
        return Err(AgentError::AuthorityRollback);
    }
    match value {
        Value::Array(values) => {
            if values.len() > policy.items {
                return Err(AgentError::AuthorityRollback);
            }
            for value in values {
                walk(value, policy, depth + 1, nodes)?;
            }
        }
        Value::Object(values) => {
            if values.len() > policy.items {
                return Err(AgentError::AuthorityRollback);
            }
            for value in values.values() {
                walk(value, policy, depth + 1, nodes)?;
            }
        }
        _ => {}
    }
    Ok(())
}
