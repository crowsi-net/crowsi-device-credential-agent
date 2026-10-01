use crate::AgentError;

pub trait AuthorityTransport: Send + Sync {
    fn route_binding_sha256(&self) -> Result<String, AgentError>;
    fn exchange(&self, command: &str, request: &[u8], now: u64) -> Result<Vec<u8>, AgentError>;
}
