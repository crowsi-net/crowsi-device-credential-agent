use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::Value;
use std::collections::BTreeMap;

use crate::{AgentError, replay::DurableLedger};

impl DurableLedger {
    pub(crate) fn verify_namespaces(&self) -> Result<(), AgentError> {
        let document = self
            .load::<SecurityNamespaces>()?
            .ok_or(AgentError::AuthorityRollback)?;
        document.validate()
    }
    pub(crate) fn load_namespace<T: DeserializeOwned>(
        &self,
        namespace: &str,
    ) -> Result<Option<T>, AgentError> {
        let Some(document) = self.load::<SecurityNamespaces>()? else {
            return Ok(None);
        };
        document.get(namespace)
    }

    #[cfg(test)]
    pub(crate) fn update_namespace<T: DeserializeOwned + Serialize>(
        &self,
        namespace: &str,
        transition: impl FnOnce(Option<&T>) -> Result<Option<T>, AgentError>,
    ) -> Result<(), AgentError> {
        self.transaction_namespaces(|document| {
            let current: Option<T> = document.get(namespace)?;
            let Some(next) = transition(current.as_ref())? else {
                return Ok(((), false));
            };
            document.put(namespace, &next)?;
            Ok(((), true))
        })
    }

    pub(crate) fn transaction_namespaces<R>(
        &self,
        transition: impl FnOnce(&mut SecurityNamespaces) -> Result<(R, bool), AgentError>,
    ) -> Result<R, AgentError> {
        let mut transition = Some(transition);
        let mut output = None;
        self.update::<SecurityNamespaces>(|current| {
            let mut document = current.cloned().unwrap_or_else(SecurityNamespaces::empty);
            document.validate()?;
            let callback = transition.take().ok_or(AgentError::AuthorityRollback)?;
            let (value, changed) = callback(&mut document)?;
            document.validate()?;
            output = Some(value);
            Ok(changed.then_some(document))
        })?;
        output.ok_or(AgentError::AuthorityRollback)
    }
}

pub(crate) fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:-".contains(&byte))
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SecurityNamespaces {
    schema: String,
    records: BTreeMap<String, Value>,
}

impl SecurityNamespaces {
    fn empty() -> Self {
        Self {
            schema: "crowsi://device-agent/security-namespaces/v1".into(),
            records: BTreeMap::new(),
        }
    }
    pub(crate) fn get<T: DeserializeOwned>(
        &self,
        namespace_name: &str,
    ) -> Result<Option<T>, AgentError> {
        if !namespace(namespace_name) {
            return Err(AgentError::AuthorityRollback);
        }
        self.records
            .get(namespace_name)
            .cloned()
            .map(|value| serde_json::from_value(value).map_err(|_| AgentError::AuthorityRollback))
            .transpose()
    }
    pub(crate) fn put<T: Serialize>(
        &mut self,
        namespace_name: &str,
        value: &T,
    ) -> Result<(), AgentError> {
        if !namespace(namespace_name) {
            return Err(AgentError::AuthorityRollback);
        }
        self.records.insert(
            namespace_name.into(),
            serde_json::to_value(value).map_err(|_| AgentError::AuthorityRollback)?,
        );
        self.validate()
    }
    fn validate(&self) -> Result<(), AgentError> {
        (self.schema == "crowsi://device-agent/security-namespaces/v1"
            && self.records.len() <= 16
            && self.records.keys().all(|key| namespace(key)))
        .then_some(())
        .ok_or(AgentError::AuthorityRollback)?;
        crate::replay_namespace_limits::validate(&self.records)
    }
}

fn namespace(value: &str) -> bool {
    matches!(
        value,
        "management-projection"
            | "identity-session-locator"
            | "device-enrollment"
            | "prepared-operation"
            | "fresh-uv-attempt"
            | "operation-journal"
            | "transport-replay"
    )
}
