use ihat_identity_assertion_contracts::{
    AUTHORITY_REQUEST_SCHEMA, AuthorityCommand, AuthorityEvidence, AuthorityRequestV1,
    IssueCurrentDeviceIdentityEvidenceCommand, command_digest,
};

use crate::{
    AgentError, config::AgentConfigDocument, identity_client::IdentityAuthorityClient,
    transport::AuthorityTransport,
};

impl<T: AuthorityTransport> IdentityAuthorityClient<T> {
    pub(crate) fn prepare_current(
        &self,
        config: &AgentConfigDocument,
        now: u64,
    ) -> Result<AuthorityRequestV1, AgentError> {
        if config.session_sender_key_fingerprint != self.sender.fingerprint() {
            return Err(AgentError::IdentityUnavailable);
        }
        let proof_id = crate::random_id::create("session-sender-proof")?;
        let mut request = AuthorityRequestV1 {
            schema: AUTHORITY_REQUEST_SCHEMA.into(),
            request_id: crate::random_id::create("identity-request")?,
            command: AuthorityCommand::IssueCurrentDeviceIdentityEvidence(
                IssueCurrentDeviceIdentityEvidenceCommand {
                    service_id: config.management_projection_trust.service_id.clone(),
                    pairwise_subject: config.management_projection_trust.pairwise_subject.clone(),
                    device_id: config.identity_authority_route.device_id.clone(),
                    audience: config.identity_audience.clone(),
                    identity_nonce: crate::random_id::create("identity-nonce")?,
                    ttl_seconds: 30,
                    session_sender_key_fingerprint: self.sender.fingerprint().into(),
                    session_sender_proof_id: proof_id.clone(),
                },
            ),
            evidence: Vec::new(),
        };
        let digest = command_digest(&request).map_err(|_| AgentError::RequestInvalid)?;
        request.evidence.push(AuthorityEvidence::Signed(
            self.sender.sign(&proof_id, &digest, now)?,
        ));
        Ok(request)
    }
}
