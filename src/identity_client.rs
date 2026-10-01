use crate::{
    AgentError, config::AgentConfigDocument, session_sender::SessionSender,
    transport::AuthorityTransport,
};
use crowsi_credential_authority_contracts::SignedAuthorityExchangeV1;

pub(crate) struct IdentityAuthorityClient<T: AuthorityTransport> {
    pub(crate) transport: T,
    pub(crate) sender: SessionSender,
    pub(crate) uid: u32,
}

impl<T: AuthorityTransport> IdentityAuthorityClient<T> {
    pub(crate) fn open(
        config: &AgentConfigDocument,
        transport: T,
        uid: u32,
    ) -> Result<Self, AgentError> {
        if transport.route_binding_sha256()? != config.identity_authority_route.binding_sha256 {
            return Err(AgentError::ConfigInvalid);
        }
        Ok(Self {
            transport,
            sender: crate::session_sender::open(config, uid)?,
            uid,
        })
    }

    pub(crate) fn issue(
        &self,
        config: &AgentConfigDocument,
        now: u64,
    ) -> Result<SignedAuthorityExchangeV1, AgentError> {
        let request = self.prepare_current(config, now)?;
        self.invoke_current(config, &request, now)
    }
}
